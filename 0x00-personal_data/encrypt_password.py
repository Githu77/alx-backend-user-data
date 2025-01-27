#!/usr/bin/env python3
"""
The encrypting passwords
"""


import bcrypt


def hash_password(password: str) -> bytes:
    """
    A salted pass generation
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ 
    check validity?
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
