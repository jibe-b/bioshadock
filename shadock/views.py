from pyramid.view import view_config
from pyramid.response import Response
from pyramid.httpexceptions import HTTPFound, HTTPNotFound, HTTPForbidden, HTTPUnauthorized, HTTPBadRequest

import json
import datetime
import time
import base64
import struct
import re
import urllib3

from bson import json_util
from bson.json_util import dumps
from bson.objectid import ObjectId
from bson.errors import InvalidId

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key, load_pem_public_key, load_ssh_public_key
    )
from cryptography.hazmat.primitives import serialization

from basicauth import decode

#request.registry.settings['admin']
#user = request.registry.db_mongo['users'].find_one({'id': user_id})

def valid_user(username, password, request):
    #TODO manage auth
    print "Add fake user for test"
    user = request.registry.db_mongo['users'].find_one({'id': username})
    if user is None:
        request.registry.db_mongo['users'].insert({'id': username})
    return True


def is_logged(request):
    '''
    Check if user is logged, return user info or None
    '''
    if request.authorization is not None:
        try:
            (type, bearer) = request.authorization
            secret = request.registry.settings['secret_passphrase']
            # If decode ok and not expired
            user = jwt.decode(bearer, secret, audience='urn:bioshadock/auth')
            return user['user']
        except Exception:
            return None
    return None

def get_token(request):
    secret = None

    private_key = None
    passphrase = None
    if request.registry.settings['private_key_passphrase']:
        passphrase = request.registry.settings['private_key_passphrase']
    with open(request.registry.settings['private_key'], 'r') as content_file:
        private_key = load_pem_private_key(content_file.read().encode('utf-8'),
                                          password=passphrase, backend=default_backend())


    pub_key = None
    pem = None
    exponent = None
    modulus = None
    with open(request.registry.settings['public_key'], 'r') as content_file:
        pub_key = content_file.read().encode('utf-8')

        pub_key = load_pem_x509_certificate(pub_key, backend=default_backend())
        pub_key = pub_key.public_key()
        pem = pub_key.public_bytes(
                  encoding=serialization.Encoding.PEM,
                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
        pub_numbers = pub_key.public_numbers()
        exponent = pub_numbers._e
        modulus= pub_numbers._n
        modulus = ('%%0%dx' % (256 << 1) % modulus).decode('hex')[-256:]
        exponent = ('%%0%dx' % (3 << 1) % exponent).decode('hex')[-3:]


    der = None
    with open(request.registry.settings['cacert_der'], 'rb') as content_file:
        der = content_file.read()


    access = []
    if scope is not None:
        scope = scope.split(':')
        type = scope[0]
        repository = scope[1]
        actions = scope[2].split(',')
        allowed_actions = []
        for action in actions:
            if action == 'push' and user_can_push(username, repository, request):
                allowed_actions.append(action)
            if action == 'pull' and user_can_pull(username, repository, request):
                allowed_actions.append(action)
        access = [
             {
               "type": type,
               "name": repository,
               "actions": allowed_actions
             }
        ]
    claims = {'iss': request.registry.settings['issuer'],
                    'sub': username,
                    'aud': service,
                    'access': access,
                    'nbf': datetime.datetime.utcnow(),
                    'iat': datetime.datetime.utcnow(),
                    'exp': datetime.datetime.utcnow()+datetime.timedelta(seconds=3600),
                    }
    print str(claims)
    token = jwt.encode(claims,
                    private_key,  algorithm='RS256',
                    headers={'jwk': {'kty': 'RSA', 'alg': 'RS256',
                                      'n': base64.urlsafe_b64encode(modulus),
                                      'e': base64.urlsafe_b64encode(exponent),
                                      'x5c': [base64.b64encode(der)]
                    }}
                    )
    return {'token': token}

@view_config(route_name='config', renderer='json', request_method='GET')
def config(request):
    config = {
        'registry': request.registry.settings['dockerregistry'],
        'service': request.registry.settings['service']
    }
    return config

@view_config(route_name='user_is_logged', renderer='json', request_method='GET')
def user_is_logged(request):
    user = is_logged(request)
    if user is None:
        return HTTPNotFound('User not logged')
    else:
        return user


@view_config(route_name='user_bind', renderer='json', request_method='POST')
def user_bind(request):
    form = json.loads(request.body, encoding=request.charset)
    uid = form['uid']
    password = form['password']
    if not valid_user(uid, password, request):
        return HTTPUnauthorized('Invalid credentials')
    user = request.registry.db_mongo['users'].find_one({'id': uid})
    secret = request.registry.settings['secret_passphrase']
    del user['_id']
    token = jwt.encode({'user': user,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600),
                        'aud': 'urn:bioshadock/auth'}, secret)
    return { 'user': user, 'token': token }

@view_config(route_name='containers', renderer='json', request_method='GET')
def containers(request):
    user = is_logged(request)
    if user is None:
        return HTTPForbidden()
    repos = request.registry.db_mongo['repository'].find({'$or': [{'user': user['id']}, {'acl_pull.members': user['id']}]})
    user_repos = []
    for repo in repos:
        user_repos.append(repo)
    return user_repos

@view_config(route_name='container_manifest', renderer='json', request_method='POST')
def container_manifest(request):
    user = is_logged(request)
    repo_id = '/'.join(request.matchdict['id'])
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if not repo['visible']:
        if user is None:
            return HTTPForbidden()
        if repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()

    form = json.loads(request.body, encoding=request.charset)
    token = form['token']
    tag = form['tag']
    http = urllib3.PoolManager()
    headers = {'Authorization': 'Bearer '+token}
    r = http.request('GET', request.registry.settings['dockerregistry']+'/v2/'+repo_id+'/manifests/'+tag, headers=headers)
    if r.status != 200:
        return Response('could not get the manifest', status_code = r.status)
    return json.loads(r.data)

@view_config(route_name='container_dockerfile', renderer='json', request_method='POST')
def container_dockerfile(request):
    user = is_logged(request)
    repo_id = '/'.join(request.matchdict['id'])
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if not repo['visible']:
        if user is None:
            return HTTPForbidden()
        if repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()
    form = json.loads(request.body, encoding=request.charset)
    dockerfile = form['dockerfile']
    request.registry.db_mongo['repository'].update({'id': repo_id},{'$set': {'meta.Dockerfile': dockerfile}})
    newbuild = {
        'id': repo_id,
        'date': datetime.datetime.now(),
        'dockerfile': dockerfile,
        'user': user['id']
    }
    request.registry.db_redis.rpush('bioshadock:builds', dumps(newbuild))
    return {}


@view_config(route_name='container_tags', renderer='json', request_method='POST')
def container_tags(request):
    user = is_logged(request)
    repo_id = '/'.join(request.matchdict['id'])
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if not repo['visible']:
        if user is None:
            return HTTPForbidden()
        if repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()

    form = json.loads(request.body, encoding=request.charset)
    token = form['token']
    http = urllib3.PoolManager()
    headers = {'Authorization': 'Bearer '+token}
    r = http.request('GET', request.registry.settings['dockerregistry']+'/v2/'+repo_id+'/tags/list', headers=headers)
    if r.status != 200:
        return Response('could not get the manifest', status_code = r.status)
    return json.loads(r.data)

@view_config(route_name='container', renderer='json', request_method='GET')
def container(request):
    user = is_logged(request)
    repo_id = '/'.join(request.matchdict['id'])
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if not repo['visible']:
        if user is None:
            return HTTPForbidden()
        if repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()
        if repo['user'] == user['id'] or user['id'] in repo['acl_push']['members']:
            repo['user_can_push'] = True
        else:
            repo['user_can_push'] = False
    return repo

@view_config(route_name='containers_search', renderer='json', request_method='POST')
def containers_search(request):
    form = json.loads(request.body, encoding=request.charset)
    search = form['search']
    user = is_logged(request)
    regx = re.compile(search, re.IGNORECASE)
    if user is None:
            repos = request.registry.db_mongo['repository'].find({'visible': True, 'id': regx})
    else:
        repos = request.registry.db_mongo['repository'].find({'$or': [{'user': user['id']}, {'acl_pull.members': user['id']}], 'id': regx})
    user_repos = []
    for repo in repos:
        user_repos.append(repo)
    return user_repos

@view_config(route_name='api_repositories_images_layer_access', renderer='json', request_method='GET')
def api_repositories_images_layer_access(request):
    '''
    Library repo
    /v1/repositories/{namespace}/{image}/layer/{id}/access
    '''
    print str(request)
    repo_id = str(request.matchdict['namespace'])+'/'+str(request.matchdict['image'])
    secret = request.registry.settings['secret_passphrase']
    token = None
    if request.authorization:
        (type, bearer) = request.authorization
        token = bearer.split(',')[0].replace('signature=','')
        try:
            msg = jwt.decode(token, secret)
        except Exception as e:
            print str(e)
            return HTTPForbidden(str(e))
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    return {'access':True}

@view_config(route_name='api_library', renderer='json', request_method='DELETE')
def api_library_delete(request):
    repo_id = None
    repo_id = 'library/'+ request.matchdict['image']
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password, request) or not user_can_delete(username, repo_id, request):
            return HTTPForbidden()
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if existing_repo is None:
        return Response()
    token = jwt.encode({'repo': repo_id,
                        'user': username,
                        'acl': 'delete',
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600*24)
                        }, secret)
    docker_token = "signature="+token+",repository=\""+repo_id+"\",access=write"
    headers = [("WWW-Authenticate", "Token "+docker_token.encode('utf8')),
               ("X-Docker-Endpoints", endpoints),("X-Docker-Token", docker_token.encode('utf8'))
              ]
    request.registry.db_mongo['repository'].remove({'id': repo_id})
    request.response.headerlist.extend(headers)
    return Response('Accepted', status_code=202, headerlist=request.response.headerlist)



@view_config(route_name='api_library', renderer='json', request_method='PUT')
def api_library_push(request):
    '''
    Library repo
    /v1/repositories/{image}
    '''
    images = json.loads(request.body, encoding=request.charset)
    repo_id = None
    repo_id = 'library/'+ request.matchdict['image']
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password, request) or not user_can_push(username, repo_id, request):
            return HTTPForbidden()
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})

    request.registry.db_mongo['repository'].update({'id': repo_id}, {"$set":{'images': images}})

    (type, bearer) = request.authorization

    token = jwt.encode({'repo': repo_id,
                        'user': username,
                        'acl': 'write',
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)
                        }, secret)
    docker_token = "signature="+token+",repository=\""+repo_id+"\",access=write"
    headers = [("WWW-Authenticate", "Token "+docker_token.encode('utf8')),
               ("X-Docker-Endpoints", endpoints),("X-Docker-Token", docker_token.encode('utf8'))
              ]
    request.response.headerlist.extend(headers)
    return Response('Created', headerlist=request.response.headerlist)


@view_config(route_name='api_library_images', renderer='json', request_method='GET')
def api_library_images(request):
    '''
    Library repo
    /v1/repositories/{image}/images
    '''
    #images = json.loads(request.body, encoding=request.charset)
    repo_id = 'library/' + request.matchdict['image']
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if existing_repo is None:
        return HTTPNotFound()
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password, request):
            return HTTPForbidden()
    (type, bearer) = request.authorization
    token = jwt.encode({'repo': repo_id,
                        'user': username,
                        'acl': 'read',
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)
                        }, secret)
    docker_token = "signature="+token+",repository=\""+repo_id+"\",access=read"
    headers = [("WWW-Authenticate", "Token "+docker_token.encode('utf8')),
               ("X-Docker-Endpoints", endpoints),("X-Docker-Token", docker_token.encode('utf8'))
              ]
    request.registry.db_mongo['repository'].update({'id': repo_id},{"$inc": { "pulls": 1}})
    request.response.headerlist.extend(headers)
    return Response(json.dumps(existing_repo['images']), headerlist=request.response.headerlist)

@view_config(route_name='api_library_images', renderer='json', request_method='PUT')
def api_library_images_push(request):
    images = json.loads(request.body, encoding=request.charset)
    repo_id = None
    repo_id = 'library/'+ request.matchdict['image']
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password, request):
            return HTTPForbidden()
    if images:
        existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
        if existing_repo is None:
            return HTTPNotFound()
        return {"access": True}
    else:
        return Response('',status_code=204)

@view_config(route_name='api_library_auth', renderer='json', request_method='PUT')
def api_library_auth(request):
    '''
    Library repo
    /v1/repositories/{image}/auth
    '''
    repo_id = 'library/'+str(request.matchdict['image'])
    secret = request.registry.settings['secret_passphrase']
    token = None
    if request.authorization:
        (type, bearer) = request.authorization
        token = bearer.split(',')[0].replace('signature=','')
        try:
            msg = jwt.decode(token, secret)
            if msg['acl'] == 'delete':
                return Reponse('')
            else:
                return HTTPForbidden()
        except Exception as e:
            print str(e)
            return HTTPForbidden(str(e))
    else:
        return HTTPForbidden()




@view_config(route_name='api_repositories_images_get', renderer='json', request_method='GET')
def api_repositories_images(request):
    '''
    Library repo
    /v1/repositories/{namespace}/{image}/images
    '''
    repo_id = str(request.matchdict['namespace'])+'/'+str(request.matchdict['image'])
    secret = request.registry.settings['secret_passphrase']
    token = None
    if request.authorization:
        (type, bearer) = request.authorization
        token = bearer.split(',')[0].replace('signature=','')
        try:
            msg = jwt.decode(token, secret)
        except Exception as e:
            print str(e)
            return HTTPForbidden(str(e))
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    images = []
    for image in repo['images']:
        images.append(image)
    return images


@view_config(route_name='api_repositories_images_put', renderer='json', request_method='PUT')
def api_repositories_images_push(request):
    '''
    Library repo
    /v1/repositories/{namespace}/{image}/images
    '''
    images = json.loads(request.body, encoding=request.charset)
    repo_id = None
    repo_id = request.matchdict['namespace'] + '/'+ request.matchdict['image']
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password, request):
            return HTTPForbidden()
    if images:
        existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
        if existing_repo is None:
            return HTTPNotFound()
        return {"access": True}
    else:
        return Response('',status_code=204)

@view_config(route_name='api_library', renderer='json', request_method='DELETE')
def api_library_delete(request):
    repo_id = None
    repo_id = request.matchdict['namespace'] + '/'+ request.matchdict['image']
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password, request) or not user_can_delete(username, repo_id, request):
            return HTTPForbidden()
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if existing_repo is None:
        return Response('')
    token = jwt.encode({'repo': repo_id,
                        'user': username,
                        'acl': 'delete',
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)
                        }, secret)
    docker_token = "signature="+token+",repository=\""+repo_id+"\",access=write"
    headers = [("WWW-Authenticate", "Token "+docker_token.encode('utf8')),
               ("X-Docker-Endpoints", endpoints),("X-Docker-Token", docker_token.encode('utf8'))
              ]
    request.registry.db_mongo['repository'].remove({'id': repo_id})
    request.response.headerlist.extend(headers)
    return Response('Accepted', status_code=202, headerlist=request.response.headerlist)

@view_config(route_name='api_repositories_auth', renderer='json', request_method='PUT')
def api_repositories_auth(request):
    '''
    Library repo
    /v1/repositories/{image}/auth
    '''
    repo_id = request.matchdict['namespace'] + '/'+str(request.matchdict['image'])
    secret = request.registry.settings['secret_passphrase']
    token = None
    if request.authorization:
        (type, bearer) = request.authorization
        token = bearer.split(',')[0].replace('signature=','')
        try:
            msg = jwt.decode(token, secret)
            if msg['acl'] == 'delete':
                return Reponse('')
            else:
                return HTTPForbidden()
        except Exception as e:
            print str(e)
            return HTTPForbidden(str(e))
    else:
        return HTTPForbidden()


@view_config(route_name='api_repositories', renderer='json', request_method='PUT')
def api_repositories_push(request):
    '''
    Library repo
    /v1/repositories/{namespace}/{image}
    '''
    images = json.loads(request.body, encoding=request.charset)
    repo_id = None
    repo_id = request.matchdict['namespace'] + '/'+ request.matchdict['image']
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password, request)or not user_can_push(username, repo_id, request):
            return HTTPForbidden()
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})

    request.registry.db_mongo['repository'].update({'id': repo_id}, {"$set":{'images': images}})

    (type, bearer) = request.authorization

    token = jwt.encode({'repo': repo_id,
                        'user': username,
                        'acl': 'write',
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)
                        }, secret)
    docker_token = "signature="+token+",repository=\""+repo_id+"\",access=write"
    headers = [("WWW-Authenticate", "Token "+docker_token.encode('utf8')),
               ("X-Docker-Endpoints", endpoints),("X-Docker-Token", docker_token.encode('utf8'))
              ]
    request.response.headerlist.extend(headers)
    return Response('Created', headerlist=request.response.headerlist)


@view_config(route_name='api_other', renderer='json')
def api_other(request):
    print "#Other v1 Route: "+str(request.matchdict['api'])
    print str(request)
    return HTTPForbidden()


@view_config(route_name='api2_other', renderer='json')
def api2_other(request):
    print "#Other v2 Route: "+str(request.matchdict['api'])
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

@view_config(route_name='api2_ping', renderer='json')
def api2_ping(request):
    print str('ping')
    headers = [("X-Docker-Registry-Config", "local"),
               ("X-Docker-Registry-Standalone", "false")
              ]
    request.response.headerlist.extend(headers)
    return Response('OK', headerlist=request.response.headerlist)

def to_bytes(n, length):
    return bytes( (n >> i*8) & 0xff for i in reversed(range(length)))

def can_push_to_library(username):
    return True

def user_can_delete(username, repository, request):
    user_repo = repository
    repos = repository.split('/')
    if len(repos) == 1:
        user_repo = 'library/'+repository
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': user_repo})
    if existing_repo is not None:
        if existing_repo['user'] == username:
            return True
        else:
            return False
    else:
        return False

def user_can_push(username, repository, request):
    user_repo = repository
    repos = repository.split('/')
    if len(repos) == 1:
        user_repo = 'library/'+repository
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': user_repo})
    if existing_repo is not None:
        if existing_repo['user'] == username or username in existing_repo['acl_push']['members']:
            return True
        else:
            return False
    else:
        if len(repos) > 1 or (len(repos) == 1 and can_push_to_library(username)):
            repo = { 'id' : user_repo, 'user': username, 'pulls': 0, 'visible': False,
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
            request.registry.db_mongo['repository'].insert(repo)
            return True
        else:
            return False

def user_can_pull(username, repository, request):
    user_repo = repository
    repos = repository.split('/')
    if len(repos) == 1:
        user_repo = 'library/'+repository
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': user_repo})
    if existing_repo is not None:
        if existing_repo['user'] == username or username in existing_repo['acl_pull']['members']:
            return True
        else:
            if existing_repo['visible']:
                return True
            else:
                return False
    else:
        return False


@view_config(route_name='api2_token', renderer='json')
def api2_token(request):
    account = None
    try:
        account = request.params['account']
    except Exception:
        pass
    service = request.params['service']
    scope = None
    try:
        scope = request.params['scope']
    except Exception:
        pass
    if request.authorization:
        # Login request
        if not is_logged(request):
            (type, bearer) = request.authorization
            username, password = decode(bearer)
            if not valid_user(username, password, request):
                return HTTPForbidden()
        else:
            username = account
        secret = None

        private_key = None
        passphrase = None
        if request.registry.settings['private_key_passphrase']:
            passphrase = request.registry.settings['private_key_passphrase']
        with open(request.registry.settings['private_key'], 'r') as content_file:
            private_key = load_pem_private_key(content_file.read().encode('utf-8'),
                                              password=passphrase, backend=default_backend())


        pub_key = None
        pem = None
        exponent = None
        modulus = None
        with open(request.registry.settings['public_key'], 'r') as content_file:
            pub_key = content_file.read().encode('utf-8')

            pub_key = load_pem_x509_certificate(pub_key, backend=default_backend())
            pub_key = pub_key.public_key()
            pem = pub_key.public_bytes(
                      encoding=serialization.Encoding.PEM,
                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
            pub_numbers = pub_key.public_numbers()
            exponent = pub_numbers._e
            modulus= pub_numbers._n
            modulus = ('%%0%dx' % (256 << 1) % modulus).decode('hex')[-256:]
            exponent = ('%%0%dx' % (3 << 1) % exponent).decode('hex')[-3:]


        der = None
        with open(request.registry.settings['cacert_der'], 'rb') as content_file:
            der = content_file.read()


        access = []
        if scope is not None:
            scope = scope.split(':')
            type = scope[0]
            repository = scope[1]
            actions = scope[2].split(',')
            allowed_actions = []
            for action in actions:
                if action == 'push' and user_can_push(username, repository, request):
                    allowed_actions.append(action)
                if action == 'pull' and user_can_pull(username, repository, request):
                    allowed_actions.append(action)
                    request.registry.db_mongo['repository'].update({'id': repository},{"$inc": { "pulls": 1}})
                if action == 'manifest' and user_can_pull(username, repository, request):
                    allowed_actions.append('pull')
            access = [
                 {
                   "type": type,
                   "name": repository,
                   "actions": allowed_actions
                 }
            ]
        claims = {'iss': request.registry.settings['issuer'],
                        'sub': username,
                        'aud': service,
                        'access': access,
                        'nbf': datetime.datetime.utcnow(),
                        'iat': datetime.datetime.utcnow(),
                        'exp': datetime.datetime.utcnow()+datetime.timedelta(seconds=3600*24),
                        }
        token = jwt.encode(claims,
                        private_key,  algorithm='RS256',
                        headers={'jwk': {'kty': 'RSA', 'alg': 'RS256',
                                          'n': base64.urlsafe_b64encode(modulus),
                                          'e': base64.urlsafe_b64encode(exponent),
                                          'x5c': [base64.b64encode(der)]
                        }}
                        )
        return {'token': token}
    return HTTPForbidden()


@view_config(route_name='api_users', renderer='json')
def api_users(request):
    user = json.loads(request.body, encoding=request.charset)
    print str(user)
    user_id = None
    existing_user = request.registry.db_mongo['users'].find_one({'id': user_id})
    if not existing_user:
        return HTTPForbidden("You must register first")
    return Response("User Created", status_code=201)


@view_config(route_name='home', renderer='json')
def my_view(request):
    return HTTPFound(request.static_url('shadock:webapp/app/'))
