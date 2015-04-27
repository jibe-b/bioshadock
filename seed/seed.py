import json
import datetime
from pymongo import MongoClient
from bson import json_util
from bson.objectid import ObjectId




mongo = MongoClient('mongodb://localhost:27017/')
db_mongo = mongo['mydockerhub']

repo = { 'id' : 'test/test1', 'user': 'osallou', 'pulls': 0, 'visible': False,
         'meta': {
                   'tags': [],
                   'terms': [],
                   'description': None,
                   'Dockerfile': "FROM ubuntu\nMAINTAINER Victor Vieux <victor@docker.com>\nLABEL Description=\"This image is used to start the foobar executable\" Vendor=\"ACME Products\" Version=\"1.0\"\nRUN apt-get update && apt-get install -y inotify-tools nginx apache2 openssh-server"                 },
         'acl_push': { 'members': [], 'groups': [] },
         'acl_pull': { 'members': [], 'groups': [] },
         'builds': []
       }
db_mongo['repository'].insert(repo)

repo = { 'id' : 'test/test2', 'user': 'test', 'pulls': 0, 'visible': False,
         'meta': {
                   'tags': [],
                   'terms': [],
                   'description': None,
                   'Dockerfile': None
                 },
         'acl_push': { 'members': ['osallou'], 'groups': [] },
         'acl_pull': { 'members': ['osallou'], 'groups': [] },
         'builds': []
       }
db_mongo['repository'].insert(repo)

repo = { 'id' : 'test/test3', 'user': 'test', 'pulls': 0, 'visible': False,
         'meta': {
                   'tags': [],
                   'terms': [],
                   'description': None,
                   'Dockerfile': None
                 },
         'acl_push': { 'members': [], 'groups': [] },
         'acl_pull': { 'members': [], 'groups': [] },
         'builds': []
       }
db_mongo['repository'].insert(repo)
