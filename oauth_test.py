from flask import Flask, redirect, request, url_for, session, render_template 
import requests
import jwt
#from jwt import exceptions as jwt_exceptions
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Use a strong secret key for session management

# Identity Provider Configuration
IDP_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
IDP_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
IDP_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"
CLIENT_ID = "GRAB_FROM_GOOGLE_ACCOUNT_IN_GCP"
CLIENT_SECRET = "GRAB_FROM_GOOGLE_ACCOUNT_IN_GCP"
REDIRECT_URI = "http://localhost:5000/callback"  # Redirect URI registered in your IdP
SCOPES = "openid email profile"

@app.route("/")
def home():
#    return "Welcome to the OIDC Example! <a href='/login'>Login</a>"
     return render_template('index.html')
@app.route("/login")
def login():
    # Redirect user to the IdP for authentication
    auth_url = (
        f"{IDP_AUTH_ENDPOINT}?response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"scope={SCOPES}&"
        f"state=xyz123"
    )
    return redirect(auth_url)

@app.route("/callback")
def callback():
    # Get the authorization code from the callback
    code = request.args.get("code")
    if not code:
        return "Error: Authorization code not received.", 400

    # Exchange the authorization code for tokens
    token_data = exchange_code_for_tokens(code)
    if "error" in token_data:
        return f"Token exchange failed: {token_data['error_description']}", 400

    # Decode and validate the ID token
    id_token = token_data["id_token"]
    decoded_id_token = decode_id_token(id_token)
    if not decoded_id_token:
        return "ID token validation failed.", 400

    # Fetch user info (optional)
    user_info = fetch_user_info(token_data["access_token"])

    # Display user information
    return f"""
    <h1>Welcome, {decoded_id_token['name']}</h1>
    <p>Email: {decoded_id_token['email']}</p>
    <p>ID Token: {id_token}</p>
    <p>Access Token: {token_data['access_token']}</p>
    <p>Additional User Info: {user_info}</p>
    <a href="/">Go back</a>
    """

def exchange_code_for_tokens(code):
    """
    Exchange authorization code for ID token and access token.
    """
    token_request_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    response = requests.post(IDP_TOKEN_ENDPOINT, data=token_request_data)
    return response.json()

def decode_id_token(id_token):
    """
    Decode and validate the ID token.
    """
    try:
        # For simplicity, skipping signature verification (use JWKS for production).
        decoded_token = jwt.decode(id_token, options={"verify_signature": False}, algorithms=["RS256"])
        return decoded_token
    except InvalidTokenError as e:
        print(f"Invalid token error: {e}")
        return None
    except ExpiredSignatureError as e:
        print(f"ID Token expired: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None
        


def fetch_user_info(access_token):
    """
    Fetch user information using the access token.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(IDP_USERINFO_ENDPOINT, headers=headers)
    return response.json()

if __name__ == "__main__":
    app.run(debug=True)
