from uuid import uuid4
from passlib.hash import pbkdf2_sha256
from flask_restful import reqparse
import datetime
from password_strength import PasswordPolicy
from email_validator import validate_email, EmailNotValidError


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
        expression_attribute_values[':p'] = hash_password(
            update_data.get('password'))

    return expression_attribute_values


def create_parser(method, resource):
    if method == 'post' and resource == 'user':
        parser = reqparse.RequestParser()
        parser.add_argument(
            'fullname',
            required=True,
            help="Fullname cannot be left blank"
        )
        parser.add_argument(
            'email',
            required=True,
            help="Email cannot be left blank"
        )
        parser.add_argument(
            'password',
            required=True,
            help="Password cannot be left blank"
        )

    if method == 'patch' and resource == 'user':
        parser = reqparse.RequestParser()
        parser.add_argument(
            'fullname',
            required=False
        )
        parser.add_argument(
            'email',
            required=False
        )
        parser.add_argument(
            'password',
            required=False
        )

    if method == 'post' and resource == 'login':
        parser = reqparse.RequestParser()
        parser.add_argument(
            'email',
            required=True,
            help="Email cannot be left blank"
        )
        parser.add_argument(
            'password',
            required=True,
            help="Password cannot be left blank"
        )

    return parser


def empty_data(data, method):
    empty_keys = []
    if method == 'post':
        for k, v in data.items():
            if len(v) == 0:
                empty_keys.append(k)
    if method == 'patch':
        for k, v in data.items():
            if v is not None and len(v) == 0:
                empty_keys.append(k)

    return empty_keys


def bad_password(password):
    policy = PasswordPolicy.from_names(
        length=6,
        uppercase=0,
        numbers=0,
        special=0,
        nonletters=0,
    )

    return policy.test(password)


def email_invalid(email):
    try:
        valid = validate_email(email, check_deliverability=False)
    except EmailNotValidError as ex:
        return str(ex)
