#!/usr/bin/env python3
"""
The Basic Auth module
"""

from api.v1.auth.auth import Auth
from typing import TypeVar, List
from models.user import User
import base64
import binascii


class BasicAuth(Auth):
    """
    the BasicAuth class
    """

    def extract_base64_authorization_header(
        self, authorization_header: str) -> str:
        """ extract auth header
        """
        if (authorization_header is None or
                not isinstance(authorization_header, str) or 
                not authorization_header.startswith("Basic ")):
                
            return None
        
        return authorization_header[6:]
        
    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """ decodes from Base64 """
        
        b64_auth_header = base64_authorization_header
        if b64_auth_header and isinstance(b64_auth_header, str):
            try:
                encode = b64_auth_header.encode('utf-8')
                base = base64.b64decode(encode)
                return base.decode('utf-8')
            except binascii.Error:
                return None
                
    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """ to extract user credentials """
        decoded_64 = decoded_base64_authorization_header
        if (decoded_64 and isinstance(decoded_64, str) and ":" in decoded_64):
            res = decoded_64.split(":", 1)
            return (res[0], res[1])
        return (None, None)
        
    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ returns user from email and password """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({"email": user_email})
        if not users:
            return None

        user = users[0]

        if not user.is_valid_password(user_pwd):
            return None

        return user
    
    
    def current_user(self, request=None) -> TypeVar('User'):
        """
        retrieves the User instance for a request
        """
        header = self.authorization_header(request)
        b64header = self.extract_base64_authorization_header(header)
        decoded = self.decode_base64_authorization_header(b64header)
        user_creds = self.extract_user_credentials(decoded)
        return self.user_object_from_credentials(*user_creds)
