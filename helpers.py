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

def create_update_expression(update_data):
    # SET fullname = :f, email = :e, password = :p
    update_expression = 'SET'
    update_components = []
    if update_data.get('fullname'):
        update_components.append(' fullname = :f')
    if update_data.get('email'):
        update_components.append(' email = :e')
    if update_data.get('password'):
        update_components.append(' password = :p')

    for item in update_components:
        update_expression += item + ','

    update_expression = update_expression[:-1]

    return update_expression

def create_expression_attribute_values(update_data):
    expression_attribute_values = {}
    if update_data.get('fullname'):
        expression_attribute_values[':f'] = update_data.get('fullname')
    if update_data.get('email'):
        expression_attribute_values[':e'] = update_data.get('email')
    if update_data.get('password'):
        expression_attribute_values[':p'] = hash_password(update_data.get('password'))
    
    return expression_attribute_values
