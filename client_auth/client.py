import os
import pkce
import json
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests

class RingCentralOAuthClient:
    def __init__(self, client_id, client_secret, redirect_uri, auth_url, token_url, api_base_url, token_path="rc_token.json"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.auth_url = auth_url
        self.token_url = token_url
        self.api_base_url = api_base_url
        self.token_path = token_path
        self.token_data = None

        if os.path.exists(self.token_path):
            with open(self.token_path, 'r') as f:
                self.token_data = json.load(f)

    def _save_token(self):
        with open(self.token_path, 'w') as f:
            json.dump(self.token_data, f)

    def clear_credentials(self):
        if os.path.exists(self.token_path):
            os.remove(self.token_path)
            print("Stored credentials cleared.")
        self.token_data = None

    def is_token_valid(self):
        return self.token_data and 'access_token' in self.token_data

    def _get_auth_code(self):
        # Generate PKCE verifier and challenge codes.
        self.code_verifier = pkce.generate_code_verifier(length=128)
        code_challenge = pkce.get_code_challenge(self.code_verifier)
        url = (
            f"{self.auth_url}?response_type=code&client_id={self.client_id}"
            f"&redirect_uri={self.redirect_uri}&code_challenge={code_challenge}&code_challenge_method=S256"
        )
        auth_code_holder = {}

        class OAuthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)
                if 'code' in query:
                    auth_code_holder['code'] = query['code'][0]
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Authorization successful. You can close this window.")
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Authorization failed.")

        server_address = ('', urlparse(self.redirect_uri).port)
        httpd = HTTPServer(server_address, OAuthHandler)
        thread = threading.Thread(target=httpd.serve_forever)
        thread.daemon = True
        thread.start()

        print(f"Opening browser to: {url}")
        webbrowser.open(url)
        # Refactor this at some point
        while 'code' not in auth_code_holder:
            pass

        httpd.shutdown()
        return auth_code_holder['code']

    def _exchange_code_for_token(self, code):
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'access_token_ttl': 600, # 10 minutes
            'code_verifier': self.code_verifier
        }
        response = requests.post(self.token_url, data=data)
        response.raise_for_status()
        self.token_data = response.json()
        self._save_token()

    def _refresh_token(self):
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.token_data['refresh_token'],
            'client_id': self.client_id
        }
        response = requests.post(self.token_url, data=data)
        response.raise_for_status()
        self.token_data = response.json()
        self._save_token()

    def authenticate(self):
        # Refactor this to check expiry of token against issue time. 
        if self.is_token_valid():
            try:
                self._refresh_token()
                print("Token refreshed.")
                return
            except Exception as e:
                print(f"Token refresh failed: {e}. Starting new login.")

        code = self._get_auth_code()
        self._exchange_code_for_token(code)
        print("Authentication successful.")

    def get_access_token(self):
        if not self.is_token_valid():
            raise Exception("No valid access token. Please authenticate first.")
        return self.token_data['access_token']

    def api_get(self, endpoint):
        headers = {'Authorization': f"Bearer {self.get_access_token()}"}
        response = requests.get(f"{self.api_base_url}{endpoint}", headers=headers)
        response.raise_for_status()
        return response.json()
