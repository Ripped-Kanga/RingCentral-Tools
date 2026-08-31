import os
import time
import pkce
import json
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import requests

JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"

# Seconds of headroom to leave before an access token's stated expiry. Tokens
# are re-minted early so a long-running module never fires a request that
# expires in flight.
EXPIRY_SKEW_SECONDS = 60


class RingCentralClientBase:
    """Shared token handling and API access for every authentication flow.

    Modules only ever call authenticate(), api_get() and api_post(), so any
    subclass that can produce an access token is a drop-in for the others.
    """

    def __init__(self, client_id, client_secret, token_url, api_base_url, token_path=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.api_base_url = api_base_url
        self.token_path = token_path
        self.token_data = None

        if self.token_path and os.path.exists(self.token_path):
            with open(self.token_path, 'r') as f:
                self.token_data = json.load(f)

    # ── Token storage ────────────────────────────────────────────────────────

    def _store_token(self, token_data):
        """Record a token response, stamping an absolute expiry so freshness
        can be checked later, and persist it if this flow uses a token file."""
        expires_in = token_data.get('expires_in')
        if expires_in:
            token_data['expires_at'] = time.time() + int(expires_in)
        self.token_data = token_data
        self._save_token()

    def _save_token(self):
        if not self.token_path:
            return
        with open(self.token_path, 'w') as f:
            json.dump(self.token_data, f)

    def clear_credentials(self):
        if self.token_path and os.path.exists(self.token_path):
            os.remove(self.token_path)
            print("Stored credentials cleared.")
        self.token_data = None

    def is_token_valid(self):
        return bool(self.token_data and 'access_token' in self.token_data)

    def _access_token_fresh(self):
        """True when we hold a token that has not reached its expiry. A token
        with no recorded expiry is treated as fresh — the caller's own refresh
        logic decides what to do with it."""
        if not self.is_token_valid():
            return False
        expires_at = self.token_data.get('expires_at')
        if not expires_at:
            return True
        return time.time() < (expires_at - EXPIRY_SKEW_SECONDS)

    # ── Token endpoint ───────────────────────────────────────────────────────

    def _token_request(self, data):
        """POST to the token endpoint. RingCentral expects client credentials
        via HTTP Basic auth for confidential apps; public (PKCE-only) apps
        send client_id in the body instead. Surfaces the API's error
        description on failure rather than a bare HTTP status."""
        auth = None
        if self.client_secret:
            auth = (self.client_id, self.client_secret)
        else:
            data['client_id'] = self.client_id

        response = requests.post(self.token_url, data=data, auth=auth)
        if response.status_code >= 400:
            try:
                err = response.json()
                print(
                    f"Token endpoint error {response.status_code}: "
                    f"{err.get('error', '')} — {err.get('error_description', response.text)}"
                )
            except ValueError:
                print(f"Token endpoint error {response.status_code}: {response.text}")
        response.raise_for_status()
        return response.json()

    def authenticate(self):
        raise NotImplementedError

    def get_access_token(self):
        if not self.is_token_valid():
            raise Exception("No valid access token. Please authenticate first.")
        return self.token_data['access_token']

    # ── API access ───────────────────────────────────────────────────────────

    def api_get(self, endpoint):
        headers = {'Authorization': f"Bearer {self.get_access_token()}"}
        response = requests.get(f"{self.api_base_url}{endpoint}", headers=headers)
        response.raise_for_status()
        return response.json()

    def api_post(self, endpoint, json_body):
        headers = {'Authorization': f"Bearer {self.get_access_token()}"}
        response = requests.post(f"{self.api_base_url}{endpoint}", headers=headers, json=json_body)
        response.raise_for_status()
        return response.json()


class RingCentralOAuthClient(RingCentralClientBase):
    """Three-legged OAuth with PKCE. Opens a browser for the user to log in,
    then exchanges the returned code for a token pair held in token_path."""

    def __init__(self, client_id, client_secret, redirect_uri, auth_url, token_url, api_base_url, token_path="rc_token.json"):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            token_url=token_url,
            api_base_url=api_base_url,
            token_path=token_path,
        )
        self.redirect_uri = redirect_uri
        self.auth_url = auth_url

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
            'access_token_ttl': 600, # 10 minutes
            'code_verifier': self.code_verifier
        }
        self._store_token(self._token_request(data))

    def _refresh_token(self):
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.token_data['refresh_token']
        }
        self._store_token(self._token_request(data))

    def authenticate(self):
        # A saved access token may already be expired while its refresh token
        # is still good, so presence — not freshness — is what decides whether
        # a refresh is worth attempting.
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


class RingCentralJWTClient(RingCentralClientBase):
    """Server-side JWT (jwt-bearer grant) authentication.

    Intended for handing tenancy access to someone who should not hold a
    RingCentral platform login: a JWT credential issued for the app grants API
    access under the issuing user's permissions and can be revoked from the
    developer console at any time without touching the tenancy's user accounts.

    The JWT itself is a long-lived secret and is never written to disk. Access
    tokens are held in memory only and re-minted from the JWT whenever they
    expire, so there is no refresh token to manage.
    """

    def __init__(self, client_id, client_secret, jwt_assertion, token_url, api_base_url, access_token_ttl=3600):
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            token_url=token_url,
            api_base_url=api_base_url,
            token_path=None,
        )
        self.jwt_assertion = jwt_assertion
        self.access_token_ttl = access_token_ttl

    def clear_credentials(self):
        """No token is persisted for this flow — clearing just drops the
        in-memory access token so the next call mints a fresh one."""
        self.token_data = None
        print("In-memory access token cleared.")

    def _mint_token(self):
        data = {
            'grant_type': JWT_GRANT_TYPE,
            'assertion': self.jwt_assertion,
            'access_token_ttl': self.access_token_ttl,
        }
        self._store_token(self._token_request(data))

    def authenticate(self):
        """Mint an access token from the JWT, unless the current one is still
        comfortably within its lifetime. Modules call this to 'refresh', which
        for JWT simply means presenting the assertion again."""
        if self._access_token_fresh():
            return
        self._mint_token()
        print("Authenticated with JWT credential.")

    def get_access_token(self):
        # Long polling modules can outlive a token between authenticate()
        # calls; minting is cheap and silent, so top it up on demand.
        if not self._access_token_fresh():
            self._mint_token()
        return self.token_data['access_token']
