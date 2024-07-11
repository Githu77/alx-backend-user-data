#!/usr/bin/env python3
"""
The auth class
"""

from tabnanny import check
from flask import request
from typing import TypeVar, List
from os import getenv
User = TypeVar('User')


class Auth:
    """
    for API authentication
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        to return False, path and excluded_paths
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
        """
        to return None - request
        """
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> User:
        """
        returns None - request
        """
        return None

    def session_cookie(self, request=None):
        """
        to return cookie from a request
        """
        if request:
            session_name = getenv("SESSION_NAME")
            return request.cookie.get(session_name, None)
