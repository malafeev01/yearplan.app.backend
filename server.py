import base64
import json
import os
from functools import wraps

import flask
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import requests
from flask import abort
from flask import request

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ["https://www.googleapis.com/auth/calendar", "https://www.googleapis.com/auth/userinfo.profile"]
API_SERVICE_NAME = 'calendar'
API_VERSION = 'v3'

app = flask.Flask(__name__)

with open('api_key.json') as json_file:
    api_key_json = json.load(json_file)

app.secret_key = api_key_json['key']


def getSessionFromJWT(token):
    """
    Function for getting session data from JWT id token
    :param token: string of id_token

    :return: dictionary with session data
    """
    token_payload = token.split('.')[1]

    padded_token = token_payload + "=" * divmod(len(token_payload), 4)[1]
    session_data = json.loads(base64.urlsafe_b64decode(padded_token))

    return session_data


def authorized(f):
    """
    Decorator for checking whether user authorized or not
    """

    @wraps(f)
    def decorated_function(*args, **kws):
        if 'credentials' not in flask.session:
            abort(401)

        try:
            credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])
            getSessionFromJWT(credentials.id_token)
        except Exception as exc:
            abort(401, description=str(exc))

        return f(*args, **kws)

    return decorated_function


class ApiCall:
    """
    Context manager for doing repeatable actions like getting credentials and creating Google Api instance
    """

    def __init__(self):
        self.credentials = None

    def __enter__(self):
        self.credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])
        return googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=self.credentials)

    def __exit__(self, error_type, value, traceback):
        flask.session['credentials'] = credentials_to_dict(self.credentials)


@app.route('/api/calendars')
@authorized
def get_calendars():
    with ApiCall() as api:
        calendars = api.calendarList().list().execute()

    return flask.jsonify(**calendars)


@app.route('/api/calendars', methods=['POST'])
@authorized
def create_calendar():
    data = request.json

    if "summary" not in data or "timeZone" not in data:
        abort(400)

    with ApiCall() as api:
        calendar = {
            "summary": data["summary"],
            "timeZone": data["timeZone"]
        }
        created_calendar = api.calendars().insert(body=calendar).execute()

    return flask.jsonify(**created_calendar)


@app.route('/api/calendars/<calendar_id>/events')
@authorized
def get_events(calendar_id):
    events_list = []
    with ApiCall() as api:
        page_token = None
        while True:
            events = api.events().list(calendarId=calendar_id, pageToken=page_token).execute()
            for event in events['items']:
                events_list.append(event)
            page_token = events.get('nextPageToken')
            if not page_token:
                break

    return flask.jsonify(events_list)


@app.route('/api/calendars/<calendar_id>/events', methods=['POST'])
@authorized
def create_event(calendar_id):
    data = request.json

    if "event" not in data:
        abort(400)

    with ApiCall() as api:
        event = api.events().insert(calendarId=calendar_id, body=data["event"]).execute()

    return flask.jsonify({'result': event})


@app.route('/api/calendars/<calendar_id>/events/<event_id>', methods=['DELETE'])
@authorized
def delete_event(calendar_id, event_id):
    with ApiCall() as api:
        api.events().delete(calendarId=calendar_id, eventId=event_id).execute()

    return flask.jsonify({})


@app.route('/api/calendars/<calendar_id>/events/<event_id>', methods=['PUT'])
@authorized
def update_event(calendar_id, event_id):
    data = request.json

    if "event" not in data:
        abort(400)

    with ApiCall() as api:
        event = api.events().update(calendarId=calendar_id, eventId=event_id, body=data["event"]).execute()

    return flask.jsonify({'result': event})


@app.route('/api/session')
@authorized
def session():
    credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])

    api = googleapiclient.discovery.build('oauth2', 'v2', credentials=credentials)
    user_info = api.userinfo().get().execute()

    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.jsonify(user_info)


@app.route('/api/login', methods=["GET"])
def login():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/api/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials

    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect('/profile')


@app.route('/api/logout')
@authorized
def logout():
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    requests.post('https://oauth2.googleapis.com/revoke',
                  params={'token': credentials.token},
                  headers={'content-type': 'application/x-www-form-urlencoded'})

    del flask.session['credentials']

    return flask.redirect('/')


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'id_token': credentials.id_token}


if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run('localhost', 8090, debug=True)
