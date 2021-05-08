from flask import Flask
from flask_restful import Resource, Api, reqparse
from flask_dynamo import Dynamo
from boto3.session import Session
from boto3.dynamodb.conditions import Attr
from helpers import generate_uuid, hash_password, password_matches, create_timestamp


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

'''
1. User POST
2. User LOGIN
3. User GET
4. User DELETE
4. Users GET
5. User PATCH
'''

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


class User(Resource):
    parser_post = reqparse.RequestParser()
    parser_post.add_argument(
            'fullname',
            required=True,
            help="Fullname cannot be left blank"
        )
    parser_post.add_argument(
            'email',
            required=True,
            help="Email cannot be left blank"
        )
    parser_post.add_argument(
            'password',
            required=True,
            help="Password cannot be left blank"
        )

    parser_patch = reqparse.RequestParser()
    parser_patch.add_argument(
            'fullname',
            required=False
        )
    parser_patch.add_argument(
            'email',
            required=False
        )
    parser_patch.add_argument(
            'password',
            required=False
        )

    def get(self, userId):
        retrieved_data = find_by_id(userId)

        if retrieved_data:
            return retrieved_data, 200

        return {'message': 'userId not found'}, 404

    def post(self):
        user_data = User.parser_post.parse_args(strict=True)
        
        if find_by_email(user_data['email']):
            return {'message': 'User with the email address provider already exists'}, 400
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
        pass

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
    parser_post_login = reqparse.RequestParser()
    parser_post_login.add_argument(
        'email',
        required=True,
        help="Email cannot be left blank"
    )
    parser_post_login.add_argument(
        'password',
        required=True,
        help="Password cannot be left blank"
    )

    def post(self):
        login_data = Login.parser_post_login.parse_args(strict=True)

        retrieved_data = find_by_email(login_data['email'])

        if retrieved_data == None:
            return {'message': 'User not found'}, 404
        
        if password_matches(login_data['password'], retrieved_data[0]['password']):
            insert_login_timestamp(retrieved_data[0]['userId'])
            return {'message': 'User authenticated'}, 200
        else:
            return {'message': 'Password validation failed'}, 403


api.add_resource(User, '/user/<string:userId>', '/user')
api.add_resource(Users, '/users')
api.add_resource(Login, '/login')

if __name__ == "__main__":
    application.run()
