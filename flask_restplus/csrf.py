import binascii
from Crypto.Cipher import AES
from flask import request, session
import os
import time

class CSRF():
    def __init__(self, expiry_window=1800, secret=None):
        """EXPIRY_WINDOW is the length of time a CSRF token lasts in seconds.

        SECRET is an encryption key, expressed in bytes.  If omitted, this
        class will generate a random key.  But note that in this case the key
        will not persist past restarts of the server.

        """
        self.expiry_window = expiry_window
        if secret:
            self.secret = secret
        else:
            self.secret = os.urandom(32)  # 256-bit random encryption key

        self.session = {}

    def decrypt(self, encrypted):
        """return ENCRYPTED as a decrypted string

        Decryption done via AES GCM and using a key of self.secret

        """
        (ciphertext, nonce, authTag) = encrypted
        aesCipher = AES.new(self.secret, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext.decode("utf-8")

    def encrypt(self, msg):
        """return MSG string encrypted via AES GCM and using a key of self.secret"""
        aesCipher = AES.new(self.secret, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(bytes(msg, 'utf-8'))
        return (ciphertext, aesCipher.nonce, authTag)

    def get_session_id(self, username):
        """This method returns the csrf session IDs that we store in memory for each
        session. from the session cookie.  If your session management is oauth
        rather than flask's session cookies, override this method to grab the
        session id from wherever your oauth implementation keeps the bearer
        token.

        This method takes the session id from the cookie on the client side.
        There is another copy of the session id.  It is wherever the app stores
        session information on the server side.

        Checking the server-side copy is more secure, but this method assumes
        you're also validating login status, which ensures the client-side
        session id matches the server-side stored session id.

        """

        if not username in self.session:
            return []

        if not 'token' in self.session[username]:
            return []

        return self.session[username]['token']

    def get_token(self, username):
        try:
            return self.session[username]['token'][-1][0]
        except:
            return ''

    def get_username(self):
        """Returns a username for the current user.  If there isn't one, return ""

        This func looks in generic places for username info.  If your system
        stores this elsewhere, override this function.
        """

        # We need a username.  Maybe we're using sessions?
        username = session.get('username', '')
        if not username:
            # Either we're not using sessions, or it's not there,
            # try just looking in the params
            username = request.values.get('username','')

        return username

    def generate_token(self, username):

        """Generate, record, and return a csrf token that is used only for CSRF
purposes.  We generate a series of new tokens because we want them to expire.
If we just made one and updated the timestamp, an old token could stick around
for a long time.

        """
        if not username in self.session:
            self.session[username] = {'token': []}
        if not 'id' in self.session[username]:
            self.session[username]['token'] = []

        token = binascii.hexlify(os.urandom(32)).decode("utf-8")
        self.session[username]['token'].append((token, time.time()))
        return token

    def logged_in(self):
        """Return true iff there is a valid login session.

        If you use some other mechanism for telling if somebody is logged in,
        override this function.

        """
        return session.get('logged_in', False)

    def logout(self):
        """Destroys the session tokens that are used only for CSRF purposes."""
        self.session[self.get_username()] = {'token': []}

    def token_valid_p(self, token, username):
        """Predicate returning true iff the TOKEN string, once unencrypted, matches the
        csrf session id string for USERNAME and is unexpired.
        """

        # Get server-side copy of tokens for this user
        ss_tokens = self.get_session_id(username)

        if ss_tokens == []:
            return False

        timestamps = [a[1] for a in ss_tokens if a[0] == token]
        if len(timestamps) == 0:
            return False

        # At this point, we know the tokens match, so we're just checking expiry
        if time.time() - timestamps[0] > self.expiry_window:
            return False

        return True

    def add_token_to_html(self, response):
        """Add the csrf token to an html response."""
        username = self.get_username()
        token = self.generate_token(username)
        data = response.data.decode("utf-8")
        data = data.replace("<head>", "<head>\n<meta name=\"csrf\" content=\"%s\">" % token, 2)
        response.data = data.encode("utf-8")
        return response
