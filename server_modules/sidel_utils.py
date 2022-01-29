from uuid import uuid4

def get_nonce():
    return uuid4().int

