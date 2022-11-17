import json
import os
import logging
import bcrypt
# Create your views here.
import validators
import base64
from django.contrib.auth.models import User
from rest_framework.decorators import parser_classes
from django.shortcuts import get_object_or_404
from django_statsd.clients import statsd
import time
import math
import random
#from boto.dynamodb2.table import Table

from django.http import JsonResponse, HttpResponse, QueryDict
from django.utils import timezone
from rest_framework.parsers import JSONParser, FileUploadParser,MultiPartParser
from django.views.decorators.csrf import csrf_exempt
from jsonschema import validate
from rest_framework import status, views
from rest_framework.authentication import BasicAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_200_OK
)
import boto3
from rest_framework.views import APIView
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())
logger = logging.getLogger(__name__)
logger.setLevel("INFO")


from .models import AccountCustom, DocCustom

schema = {
    "type": "object",
    "properties": {
        "first_name": {"type": "string"},
        "last_name": {"type": "string"},
        "password": {"type": "string"},
    }
}

client = boto3.client(
            's3'
        )


def index(request):
    if request.method == 'POST':

        try:
            statsd.incr('api.userCreate')
            t = statsd.timer('api.userCreate.time.taken')
            t.start()
            json_data = json.loads(request.body)
            if "username" not in json_data:
                raise BaseException("username should be present")
            valid = validators.email(json_data['username'])
            if not valid:
                raise BaseException("username should be a valid email")

            user = User.objects.create_user(json_data['username'], json_data['username'], json_data['password'])
            user.first_name = json_data['first_name']
            user.last_name = json_data['last_name']
            user.save()
            hashed = bcrypt.hashpw(json_data['password'].encode("utf-8"), bcrypt.gensalt())
            usercustom = AccountCustom(
                first_name=user.first_name,
                last_name=user.last_name,
                username=user.username,
                password=hashed,
            )
            usercustom.save()
            dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
            #table = dynamodb.Table('Account')

            sns = boto3.client('sns', region_name='us-east-1')
            digits = [i for i in range(0, 10)]
            random_str = ""
            for i in range(6):
                index = math.floor(random.random() * 10)
                random_str += str(digits[index])
            print(random_str)
            seconds = 300
            ttl = int(time.time()) + seconds
            #existing_tables = dynamodb.list_tables()['TableNames']

            #print(dynamodb)
            #response = dynamodb.describe_table(TableName='Account')
            # if not response:
            existing_tables = dynamodb.get_available_subresources()
            print(existing_tables)
            dbclient = boto3.client('dynamodb', region_name='us-east-1')
            response = dbclient.list_tables()#dbclient.describe_table(TableName='Account') or 1
            print(response)
            #tables = list(dynamodb.Tables.all())
            #if dynamodb.Table('Account'):
            #    print("yayyy")
            if 'Account' not in response['TableNames'] :
                 table = dynamodb.create_table(
                    TableName='Account',
                    KeySchema=[
                        {
                            'AttributeName': 'email',
                            'KeyType': 'HASH'  # Partition key
                        },
                        {
                            'AttributeName': 'token',
                            'KeyType': 'RANGE'  # Sort key
                        },

                    ],
                    AttributeDefinitions=[
                        {
                            'AttributeName': 'email',
                        # AttributeType defines the data type. 'S' is string type and 'N' is number type
                            'AttributeType': 'S'
                        },
                        {
                            'AttributeName': 'token',
                            'AttributeType': 'N'
                        },
                    ],
                    ProvisionedThroughput={
                    # ReadCapacityUnits set to 10 strongly consistent reads per second
                        'ReadCapacityUnits': 10,
                        'WriteCapacityUnits': 10  # WriteCapacityUnits set to 10 writes per second
                    }

                    )
                 table.wait_until_exists()
            #time.sleep(2)
            #return table
            #response = dynamodb.describe_table(TableName='Account')
            #print(response)
            #table = dynamodb.Table('Account')
            user_cred_email = str(json_data['username'])
            #existing_tables = dynamodb.get_available_subresources()
            #print(table.table_status)
            #print(existing_tables)
            #table = [dynamodb.tables.all()]
            #print(table)
            client = boto3.resource('dynamodb')
            if 1==1:
                    response1 = dbclient.put_item(TableName = 'Account',
                    Item={
                        'email': {'S': user_cred_email},
                        'token':{'N': random_str},
                        'TimeToLive':{'N': str(ttl)},
                    })
                    sns.publish(
                    TopicArn='arn:aws:sns:us-east-1:' + '094363902806' + ':csye6225-myTopic',
                    MessageStructure='json',
                    Message=json.dumps({'default': json.dumps({
                        'Email': json_data['username'],
                        'token': random_str
                    })}),
                    )

            logger.info("POST: Create User")
            t.stop()
            statsd.incr('api.userCreate')

            return JsonResponse(
                {
                    "id": usercustom.id,
                    "first_name": usercustom.first_name,
                    "last_name": usercustom.last_name,
                    "username": usercustom.username,
                    "account_created": usercustom.account_created,
                    "account_updated": usercustom.account_updated
                }, safe=False, status=201)

        except BaseException as err:
            return JsonResponse(str(err), status=status.HTTP_400_BAD_REQUEST, safe=False)





@authentication_classes([BasicAuthentication])
@permission_classes([IsAuthenticated])
@csrf_exempt
@api_view(["GET", "PUT"])
def self(request,id):
    if request.method == 'GET':
        statsd.incr('api.getUser')
        t = statsd.timer('api.getUser.time.taken')
        try:

            t.start()

            custom_user = User.objects.get(username=request.user.username)
            fetched_user = AccountCustom.objects.get(id=id)
            if str(custom_user) != str(fetched_user.username):
                return  JsonResponse("Sorry you cannot access others information", status=status.HTTP_403_FORBIDDEN, safe=False)
            #print(custom_user)
            #print(fetched_user.username)
            #print(custom_user.password)
            #if fetched_user.password != custom_user.password:
            #    return JsonResponse("Unauthorized", status=status.HTTP_401_UNAUTHORIZED, safe=False)
            t.stop()
            return Response({"id": fetched_user.id,
                             "first_name": fetched_user.first_name,
                             "last_name": fetched_user.last_name,
                             "username": fetched_user.username,
                             "account_created": fetched_user.account_created,
                             "account_updated": fetched_user.account_updated},
                            status=HTTP_200_OK)
        except BaseException as err:
            return JsonResponse(str(err), status=status.HTTP_400_BAD_REQUEST, safe=False)
    else:

        # tutorial_serializer = UserCustomSerializer(request.body)
        statsd.incr('api.updateUser')
        t = statsd.start('api.updateUser.time.taken').start()
        try:
            custom_user = User.objects.get(username=request.user.username)
            fetched_user = AccountCustom.objects.get(id=id)
            if str(custom_user) != str(fetched_user.username):
                return  JsonResponse("Sorry you cannot access others information", status=status.HTTP_403_FORBIDDEN, safe=False)
            #if not fetched_user.verified:
            #    return JsonResponse("Unauthorized", status=status.HTTP_401_UNAUTHORIZED, safe=False)
            auth_user = User.objects.get(username=request.user.username)
            tutorial_serializer = json.loads(request.body)
            validate(tutorial_serializer, schema)
            if "username" in tutorial_serializer:
                raise BaseException("username can't be changed")
            if tutorial_serializer['first_name'] is not None:
                fetched_user.first_name = tutorial_serializer['first_name']
                auth_user.first_name = tutorial_serializer['first_name']
            if tutorial_serializer['last_name'] is not None:
                fetched_user.last_name = tutorial_serializer['last_name']
                auth_user.last_name = tutorial_serializer['last_name']
            if tutorial_serializer['password'] is not None:
                auth_user.set_password(tutorial_serializer['password'])
            #  fetched_user.password = tutorial_serializer['password']
            # request.user.password = tutorial_serializer['password']
            auth_user.save()
            fetched_user.account_updated = timezone.now()
            hashed = bcrypt.hashpw(tutorial_serializer['password'].encode("utf-8"), bcrypt.gensalt())
            fetched_user.password = hashed
            fetched_user.save()
            logger.info("PUT: update USER")
            t.stop()
            #statsd.stop('api.updateUser.time.taken')
            return HttpResponse(status=204)
        except BaseException as err:
            logger.error("ERROR: Something Happened: PUT : Update User")
            t.stop()
            #statsd.stop('api.updateUser.time.taken')
            return JsonResponse(str(err), status=status.HTTP_400_BAD_REQUEST, safe=False)




class FileUploadView(views.APIView):
    parser_classes = (MultiPartParser,)
    authentication_classes = [BasicAuthentication]
    #permission_classes = [IsAuthenticated]
    # def post(self, request, filename, format=None):
    #     file_obj = request.data['file']
    #     # ...
    #     # do some stuff with uploaded file
    #     # ...
    #     return Response(status=204)

    def post(self,request,format=None):
        if request.method == 'POST':
            statsd.incr('api.uploadDoc')
            t= statsd.timer('api.uploadDoc.time.taken').start()
            fetched_user = AccountCustom.objects.get(username=request.user.username)
            print(request.data)
            file = request.data.get('file')
        #print(file)
            f = file.read()#base64.b64encode(file.read()).decode('utf-8')  # open(file, 'rb')#base64.b64encode(file.read())#.decode('utf-8')
            # print(type(f))# open(file,'rb')
            # obj.put('body': File.open(file, 'rb'))
        #return Response(status=204)
            try:
                #assert isinstance(file.name, object)
                response = client.put_object(
                            Bucket=os.environ['awss3bucket'],
                            Body=f,
                            Key=str(fetched_user.id) + '/' + file.name
                            )
        #return JsonResponse({response})
                check_files = DocCustom.objects.filter(user_id= fetched_user.id).values()
                for key in check_files:
                    #print(key.values_list('name'))
                    #for q in key.items():
                    #    print(q.name)
                    print(key['name'])
                    #q = QueryDict(key)
                    #for key1 in key.values():
                    #    print(key1)
                    #print(q)
                    print(file.name)

                    if key['name'] == file.name:
                        print("Oh no")
                        pic_user = DocCustom.objects.get(doc_id=key['doc_id'])
                        pic_user.delete()

                piccustom = DocCustom(
                    name=file.name,
                    s3_bucket_path=os.environ['awss3bucket'] + '/' + str(fetched_user.id) + '/' + file.name,
                    date_created=timezone.now(),
                    user_id=fetched_user.id,
                )
                # check_files = DocCustom.objects.get(user_id=fetched_user.id,name = file.)
                # if check_files.name == file.name:
                #     print("Oh no")
                #     pic_user = DocCustom.objects.get(name=str(file.name))
                #     print("File already present overwriting it")
                #     pic_user.delete()
                piccustom.save()
                # print(response)
                t.stop()
                #statsd.stop('api.uploadDoc.time.taken')
                logger.info("POST: Uploaded Document")

                return JsonResponse(
                    {
                        "doc_id": piccustom.doc_id,
                        "user_id": fetched_user.id,
                        "name": piccustom.name,
                        "s3_bucket_path": piccustom.s3_bucket_path,
                        "date_created": piccustom.date_created,
                    }, safe=False, status=201)

            except BaseException as err:
                logger.error("ERROR: Something Happened: POST : upload")
                t.stop()
                #statsd.stop('api.uploadDoc.time.taken')
                return JsonResponse(str(err), status=status.HTTP_400_BAD_REQUEST, safe=False)
    def get(self,request,format=None):
        if request.method == 'GET':
            statsd.incr('api.getDoc')
            t= statsd.timer('api.getDoc.time.taken').start()
            fetched_user = User.objects.get(username=request.user.username)
            mapped_user = AccountCustom.objects.get(username=str(fetched_user))

            try:
                print(mapped_user)

                all_docs = DocCustom.objects.filter(user_id=mapped_user.id).values()
                #if all_docs == None:

                # return Response({"doc_id": pic_user.id,
                #                 "name": pic_user.name,
                #                 "s3_bucket_path": pic_user.s3_bucket_path,
                #                 "date_created": pic_user.date_created,
                #                 "user_id": pic_user.user_id},
                #                 status=HTTP_200_OK)
                #statsd.stop('api.getDoc.time.taken')
                t.stop()
                logger.info("GET: get document")

                return Response(all_docs,status=HTTP_200_OK)
            except BaseException as err:
                logger.error("ERROR: Something Happened: GET : get document")
                t.stop()
                #statsd.stop('api.getDoc.time.taken')
                return JsonResponse(str(err), status=status.HTTP_404_NOT_FOUND, safe=False)

class Myendpointview(views.APIView):
    #authentication_classes = [BasicAuthentication]
    #permission_classes = [IsAuthenticated]
    def get(self,request,*args,**kwargs):
        if request.method == 'GET':
            statsd.incr('api.getThatDoc')
            t= statsd.timer('api.getThatDoc.time.taken').start()

            #return Response(status=HTTP_200_OK)
            #print(docu_id)
            id = kwargs.get('id')
            print(id)
            try:
                fetched_user_id = DocCustom.objects.get(doc_id=id)
            except DocCustom.DoesNotExist:
                return Response('Document no  longer present ', status=status.HTTP_404_NOT_FOUND)

            #if  not fetched_user_id:

            custom_user = User.objects.get(username=request.user.username)
            mapped_user = AccountCustom.objects.get(id=fetched_user_id.user_id)
            if str(custom_user) != str(mapped_user.username):
                return JsonResponse("Sorry you cannot access others information", status=status.HTTP_403_FORBIDDEN,
                                    safe=False)
            #account_user = DocCustom.objects.get(doc_id=docu_id)

            #if str(custom_user) != str(fetched_user.username):
            #    return JsonResponse("Sorry you cannot access others information", status=status.HTTP_403_FORBIDDEN,
            #                        safe=False)

            print(fetched_user_id)
            try:
                pic_user = DocCustom.objects.get(doc_id=fetched_user_id.doc_id)
                t.stop()
                #statsd.stop('api.getThatDoc.time.taken')
                logger.info("GET: get that document")

                return Response({"id": pic_user.doc_id,
                                 "file_name": pic_user.name,
                                 "url": pic_user.s3_bucket_path,
                                 "upload_date": pic_user.date_created,
                                 "user_id": pic_user.user_id},
                                status=HTTP_200_OK)
            except BaseException as err:
                logger.error("ERROR: Something Happened: GET : get profile pic")
                t.stop()
                #statsd.stop('api.getThatDoc.time.taken')
                return JsonResponse(str(err), status=status.HTTP_404_NOT_FOUND, safe=False)

    def delete(self,request,*args,**kwargs):
        if request.method == "DELETE":
            statsd.incr('api.deleteDoc')
            t= statsd.timer('api.deleteDoc.time.taken').start()
            #fetched_user = AccountCustom.objects.get(username=request.user.username)
            id = kwargs.get('id')
            try:
                fetched_user_id = DocCustom.objects.get(doc_id=id)
            except DocCustom.DoesNotExist:
                return Response('Document no  longer present ', status=status.HTTP_404_NOT_FOUND)

            custom_user = User.objects.get(username=request.user.username)
            mapped_user = AccountCustom.objects.get(id=fetched_user_id.user_id)
            if str(custom_user) != str(mapped_user.username):
                return JsonResponse("Sorry you cannot access others information", status=status.HTTP_403_FORBIDDEN,
                                    safe=False)
            #fetched_user_id = DocCustom.objects.get(doc_id=id)
            #mapped_user = AccountCustom.objects.get(id=fetched_user_id.user_id)
            pic_user = DocCustom.objects.get(doc_id=fetched_user_id.doc_id)
            try:
                response = client.delete_object(
                    Bucket=os.environ['awss3bucket'],
                    Key=str(mapped_user.id) + '/' + pic_user.name
                )
                print(response)

                #statsd.stop('api.deleteDoc.time.taken')
                pic_user.delete()
                logger.info("DELETE: delete profile pic")
                t.stop()

                return HttpResponse(status=204)
            except BaseException as err:
                logger.info("DELETE: delete document")
                t.stop()
                #statsd.stop('api.deleteDoc.time.taken')
                return JsonResponse(str(err), status=status.HTTP_404_NOT_FOUND, safe=False)


class Myemailverify(views.APIView):
    @csrf_exempt
    def get(self,request,*args,**kwargs):
        if request.GET['email'] and request.GET['token']:
            dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
            table = dynamodb.Table('Account')
            logger.info(request)
            logger.info(request.GET['token'])
            logger.info(request.GET['email'])
            response = table.get_item(
                Key={
                    'username': request.GET['email'],
                    'token': request.GET['token']
                })

            print(response)
            if 'Item' not in response:
                raise BaseException("email not valid for verification")
            if response['Item']['token'] == request.GET['token'] and response['Item']['TimeToLive'] > int(time.time()):
                fetched_user = User.objects.get(username=request.GET['email'])
                custom_user = AccountCustom.objects.get(id=fetched_user.id)
                custom_user.verified = True
                custom_user.save()
                return HttpResponse(status=200)
            return JsonResponse("Token Expired", status=status.HTTP_400_BAD_REQUEST, safe=False)
        else:
            return JsonResponse("email and token should be present", status=status.HTTP_400_BAD_REQUEST, safe=False)







