from pyramid.view import view_config
from pyramid.response import Response
from pyramid.httpexceptions import HTTPFound, HTTPNotFound, HTTPForbidden, HTTPUnauthorized, HTTPBadRequest

import json
import datetime

from bson import json_util
from bson.json_util import dumps
from bson.objectid import ObjectId
from bson.errors import InvalidId

import jwt

from basicauth import decode

#request.registry.settings['admin']
#user = request.registry.db_mongo['users'].find_one({'id': user_id})

def valid_user(username, password):
    return True

@view_config(route_name='api_repositories', renderer='json', request_method='PUT')
def api_repositories(request):
    '''
    Library repo
    /v1/repositories/*repo/
    '''
    images = json.loads(request.body, encoding=request.charset)
    repo_id = 'library/' + '/'.join(request.matchdict['repo'])
    print 'Allocate new repository: '+str(repo_id)
    #    WWW-Authenticate: Token
    #    signature=123abc,repository="foo/bar",access=write
    #    X-Docker-Endpoints: registry.docker.io [, registry2.docker.io]
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
    if not valid_user(username, password):
        return HTTPForbidden()
    repo = { 'id' : repo_id, 'images': images, 'user': username }
    request.registry.db_mongo['repository'].update({'id': repo_id}, repo, upsert=True)
    (type, bearer) = request.authorization
    token = jwt.encode({'repo': repo_id,
                        'user': username,
                        'acl': 'write',
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600),
                        'aud': 'urn:mydockerhub/api'}, secret)
    docker_token = "signature="+token+",repository=\""+repo_id+"\",access=write"
    headers = [("WWW-Authenticate", "Token "+docker_token.encode('utf8')),
               ("X-Docker-Endpoints", endpoints),("X-Docker-Token", docker_token.encode('utf8'))
              ]
    request.response.headerlist.extend(headers)
    print str(request.response.headerlist)
    return Response('Created', headerlist=request.response.headerlist)


@view_config(route_name='api_other', renderer='json')
def api_other(request):
    print str(request.matchdict['api'])
    print str(request)
    return Response('OK')

@view_config(route_name='api_ping', renderer='json')
def api_ping(request):
    print str('ping')
    headers = [("X-Docker-Registry-Config", "local"),
               ("X-Docker-Registry-Standalone", "false")
              ]
    request.response.headerlist.extend(headers)
    return Response('OK', headerlist=request.response.headerlist)


@view_config(route_name='api_users', renderer='json')
def api_users(request):
    user = json.loads(request.body, encoding=request.charset)
    print str(user)
    return Response("User Created", status_code=201)


@view_config(route_name='home', renderer='templates/mytemplate.pt')
def my_view(request):
    repo_id="library/test"
    secret = request.registry.settings['secret_passphrase']
    token = jwt.encode({'repo': repo_id,
                        'user': "fake",
                        'acl': 'write',
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600),
                        'aud': 'urn:mydockerhub/api'}, secret)
    docker_token = "signature="+token+",repository=\""+repo_id+"\",access=write"
    headers = [("WWW-Authenticate", "Token "+docker_token),
               ("X-Docker-Endpoints", "TEST"),("X-Docker-Token", docker_token)
              ]
    request.response.headerlist.extend(headers)
    return Response('OK', headerlist=request.response.headerlist)
