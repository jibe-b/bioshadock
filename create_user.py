import argparse
import sys
from hashlib import sha1
from random import randint
import bcrypt
import ConfigParser, os
from hashlib import sha1
from pymongo import MongoClient


parser = argparse.ArgumentParser(description='Initialize database content.')
parser.add_argument('--config')
parser.add_argument('--pwd')
parser.add_argument('--id')
parser.add_argument('--email')
args = parser.parse_args()

if not args.config:
    print "config argument is missing"
    sys.exit(2)

config = ConfigParser.ConfigParser()
config.readfp(open(args.config))

if not args.id:
    print 'id parameter is missing'
    sys.exit(1)

mongo = MongoClient(config.get('app:main','mongo_url'))
db = mongo['mydockerhub']


user_in_db = db['users'].find_one({'id': args.id})
if user_in_db is not None:
    print "User already exists"
    sys.exit(1)

email = None
if args.email:
    email = args.email

user_password = bcrypt.hashpw(args.pwd, bcrypt.gensalt())
db['users'].insert({'id': args.id,
                    'email': email,
                    'password': user_password,
                    'role': 'editor'
                    })
