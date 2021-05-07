from uuid import uuid4
from passlib.hash import pbkdf2_sha256
import datetime

def generate_uuid():
    return str(uuid4())

def hash_password(password):
    return pbkdf2_sha256.hash(password)

def password_matches(password, hash):
    return pbkdf2_sha256.verify(password, hash)
    
def create_timestamp():
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()