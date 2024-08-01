#!/usr/bin/env python3
""" this Returns a salted, hashed password, byte in string """
import bcrypt


def hash_password(password: str) -> bytes:
    """ this Returns byte string password """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ this Implement is_valid to validate provided password
    matched hashed_password
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
