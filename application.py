from flask import Flask
from flask_restful import Resource, Api, reqparse
from flask_dynamo import Dynamo
from boto3.session import Session


application = Flask(__name__)
api = Api(application)

boto_sess = Session(region_name="eu-west-2")

application.config['DYNAMO_TABLES'] = [
    {
         'TableName':  'ItemTableWithImages',
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


class User(Resource):
    parser_post = reqparse.RequestParser()
    parser_post.add_argument(
            'name',
            type=string,
            required=True,
            help="Name cannot be left blank"
        )
    parser_post.add_argument(
            'email',
            type=string,
            required=True,
            help="Email cannot be left blank"
        )
    parser_post.add_argument(
            'password',
            type=string,
            required=True,
            help="Password cannot be left blank"
        )

    parser_patch = reqparse.RequestParser()
    parser_patch.add_argument(
            'name',
            type=string,
            required=False
        )
    parser_patch.add_argument(
            'email',
            type=string,
            required=False
        )
    parser_patch.add_argument(
            'password',
            type=string,
            required=False
        )

    def get(self, name):
        pass

    def post(self, name):
        pass

    def patch(self, name):
        pass

    def delete(self, name):
        pass


class Users(Resource):
    pass


class Login(Resource):
    pass


api.add_resource(User, '/user/<string:userId>')
api.add_resource(Users, '/users')
api.add_resource(Login, '/login')

if __name__ == "__main__":
    application.run()
