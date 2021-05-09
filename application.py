from flask import Flask
from flask_restful import Resource, Api
from flask_dynamo import Dynamo
from boto3.session import Session
from boto3.dynamodb.conditions import Attr
from helpers import generate_uuid, hash_password, password_matches, create_timestamp, create_update_expression, create_expression_attribute_values, create_parser, empty_data, bad_password, email_invalid


application = Flask(__name__)
api = Api(application)

boto_sess = Session(region_name="eu-west-2")

application.config['DYNAMO_TABLES'] = [
    {
         'TableName':  'UserDatabase',
         'AttributeDefinitions': [{
             'AttributeName': 'userId',
             'AttributeType': 'S'
         }],
         'KeySchema': [{
             'AttributeName': 'userId',
             'KeyType': 'HASH'
         }],
         'BillingMode': 'PAY_PER_REQUEST'
    }
]
application.config['DYNAMO_SESSION'] = boto_sess

dynamo = Dynamo(application)

with application.app_context():
    dynamo.create_all()


def find_by_email(email):
    result = dynamo.tables['UserDatabase'].scan(
        ProjectionExpression='email,password,userId',
        FilterExpression=Attr('email').eq(email)
    )
    
    if len(result['Items']) != 0:
        return result['Items']

def find_by_id(userId):
    result = dynamo.tables['UserDatabase'].get_item(Key={
            'userId': userId
            }
        )

    if 'Item' in result:
        return {'fullname': result['Item']['fullname'], 'email': result['Item']['email'], 'lastLoginDateTime': result['Item']['lastLoginDateTime']} if 'lastLoginDateTime' in result['Item'] else {'fullname': result['Item']['fullname'], 'email': result['Item']['email']}
    
    
def insert_login_timestamp(userId):
    dynamo.tables['UserDatabase'].update_item(Key={
            'userId': userId
            },
            UpdateExpression='SET lastLoginDateTime = :l',
            ExpressionAttributeValues={
                ':l': create_timestamp()
            }
        )

def update_by_id(userId, update_data):
    dynamo.tables['UserDatabase'].update_item(Key={
            'userId': userId
            },
            UpdateExpression=create_update_expression(update_data),
            ExpressionAttributeValues=create_expression_attribute_values(update_data)
        )


class User(Resource):
    def get(self, userId):
        retrieved_data = find_by_id(userId)

        if retrieved_data:
            return retrieved_data, 200

        return {'message': f'userId {userId} not found'}, 404

    def post(self):
        parser = create_parser('post', 'user')
        user_data = parser.parse_args(strict=True)

        empty_values = empty_data(user_data, 'post')

        if empty_values:
            return {'message': f'The following keys have empty values: {str(empty_values)}'}, 400

        if find_by_email(user_data['email']):
            return {'message': 'User with the email address provided already exists'}, 400

        if bad_password(user_data['password']):
            return {'message': f'Password does not meet complexity requirements {str(bad_password(user_data["password"]))}'}, 400

        if email_invalid(user_data['email']):
            return {'message': f'Email invalid: {email_invalid(user_data["email"])}'}, 400

        userId = generate_uuid()
        try:
            dynamo.tables['UserDatabase'].put_item(Item={
                'fullname': user_data['fullname'],
                'email': user_data['email'],
                'password': hash_password(user_data['password']),
                'userId': userId
            }
        )
        except Exception as ex:
            return {'message': f'An error occurred creating the user: {ex}'}, 500

        return {'fullname:': user_data['fullname'], 'email': user_data['email'], 'userId': userId}, 201

    def patch(self, userId):
        parser = create_parser('patch', 'user')
        update_data = parser.parse_args(strict=True)

        empty_values = empty_data(update_data, 'patch')

        if empty_values:
            return {'message': f'The following keys have empty values: {str(empty_values)}'}, 400

        if list(update_data.values()) == [None, None, None]:
            return {'message': 'No user attributes to update provided'}, 400

        if find_by_id(userId) == None:
            return {'message': f'userId {userId} not found'}, 404

        if update_data.get('email'):
            if email_invalid(update_data['email']):
                return {'message': f'Email invalid: {email_invalid(update_data["email"])}'}, 400
            found = find_by_email(update_data['email'])
            if found != None and found[0]['userId'] != userId:
                return {'message': 'User with the email address provided already exists'}, 400

        if update_data.get('password'):
            if bad_password(update_data['password']):
                return {'message': f'Password does not meet complexity requirements {str(bad_password(update_data["password"]))}'}, 400

        update_by_id(userId, update_data)

        return find_by_id(userId), 200

    def delete(self, userId):
        try: 
            result = dynamo.tables['UserDatabase'].delete_item(Key={
                    'userId': userId
                },
                ReturnValues='ALL_OLD'
            )
        except Exception as ex:
            return {'message': f'An error occurred deleting the user: {ex}'}, 500
        
        if 'Attributes' in result:
            return {'message': f'userId {userId} was deleted'}, 200
            
        return {'message': f'userId {userId} does not exist'}, 404


class Users(Resource):
    def get(self):
        try:
            result = dynamo.tables['UserDatabase'].scan(
                ProjectionExpression='fullname,email,userId,lastLoginDateTime'
            )
        except Exception as ex:
            return {'message': f'An error occurred retrieving the users: {ex}'}, 500
        
        return result['Items'], 200


class Login(Resource):
    def post(self):
        parser = create_parser('post', 'login')
        login_data = parser.parse_args(strict=True)

        retrieved_data = find_by_email(login_data['email'])

        if retrieved_data == None:
            return {'message': 'User not found'}, 404
        
        if password_matches(login_data['password'], retrieved_data[0]['password']):
            insert_login_timestamp(retrieved_data[0]['userId'])
            return {'message': 'User authenticated'}, 200
        
        return {'message': 'Password validation failed'}, 403


api.add_resource(User, '/user/<string:userId>', '/user')
api.add_resource(Users, '/users')
api.add_resource(Login, '/login')

if __name__ == "__main__":
    application.run()
