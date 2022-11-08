from hashlib import sha256
from constants import SALT

def getHash(input: str) -> str:
    return sha256(f"{SALT}{input}".encode()).hexdigest()
