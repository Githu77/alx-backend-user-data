from tabnanny import check
from flask import request
from typing import TypeVar, List

class Auth:
    """ This is to manage API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ returns False - path and excluded_paths
        """
        check = path
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != "/":
            check += "/"
        if check in excluded_paths or path in excluded_paths:
            return False
        return True
        
    def authorization_header(self, request=None) -> str:
        """ returns None - request and is flask request object
        """
        if request is None:
            return none
        return request.headers.get("Authorization")
        
    def current_user(self, request=None) -> TypeVar('User'):
        """ returns None - request and is flask request object
        """
