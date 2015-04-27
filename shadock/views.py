from pyramid.view import view_config
from pyramid.response import Response
from pyramid.httpexceptions import HTTPFound, HTTPNotFound, HTTPForbidden, HTTPUnauthorized, HTTPBadRequest

import json
import datetime
import time
import base64
import struct

import jose

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

from Crypto.Util.number import long_to_bytes

from basicauth import decode

#request.registry.settings['admin']
#user = request.registry.db_mongo['users'].find_one({'id': user_id})

def valid_user(username, password):
    return True

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
            print "Token: "+str(msg)
        except Exception as e:
            print str(e)
            return HTTPForbidden(str(e))
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    return {'access':True}

@view_config(route_name='api_library', renderer='json', request_method='DELETE')
def api_library_delete(request):
    print str(request)
    print "#Route: "+str(request.matchdict['image'])
    repo_id = None
    repo_id = 'library/'+ request.matchdict['image']
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password):
            return HTTPForbidden()
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if existing_repo is None:
        return Response()
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



@view_config(route_name='api_library', renderer='json', request_method='PUT')
def api_library_push(request):
    '''
    Library repo
    /v1/repositories/{image}
    '''
    print str(request)
    print "#Route: "+str(request.matchdict['image'])
    images = json.loads(request.body, encoding=request.charset)
    print "Images: "+str(images)
    repo_id = None
    repo_id = 'library/'+ request.matchdict['image']
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password):
            return HTTPForbidden()
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if existing_repo is not None and images:
        request.registry.db_mongo['repository'].update({'id': repo_id}, {"$set":{'images': images}})
    else:
        repo = { 'id' : repo_id, 'images': images, 'user': username, 'pulls': 0, 'visible': True }
        request.registry.db_mongo['repository'].insert(repo)
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
    print str(request)
    print "#Route: library/"+str(request.matchdict['image'])
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
        if not valid_user(username, password):
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
    print str(request)
    print "#Route: "+str(request.matchdict['image'])
    images = json.loads(request.body, encoding=request.charset)
    print "Images: "+str(images)
    repo_id = None
    repo_id = 'library/'+ request.matchdict['image']
    #print 'Allocate new repository: '+str(repo_id)
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
    print str(request)
    print "#Route: "+str(request.matchdict['namespace'])+'/'+str(request.matchdict['image'])
    repo_id = 'library/'+str(request.matchdict['image'])
    #images = json.loads(request.body, encoding=request.charset)
    #print str(images)
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
    print str(request)
    print "#Route: "+str(request.matchdict['namespace'])+'/'+str(request.matchdict['image'])
    repo_id = str(request.matchdict['namespace'])+'/'+str(request.matchdict['image'])
    #images = json.loads(request.body, encoding=request.charset)
    #print str(images)
    secret = request.registry.settings['secret_passphrase']
    token = None
    if request.authorization:
        (type, bearer) = request.authorization
        token = bearer.split(',')[0].replace('signature=','')
        try:
            msg = jwt.decode(token, secret)
            print "Token: "+str(msg)
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
    print str(request)
    print "#Route: "+str(request.matchdict['repo'])
    images = json.loads(request.body, encoding=request.charset)
    print "Images: "+str(images)
    repo_id = None
    repo_id = request.matchdict['namespace'] + '/'+ request.matchdict['image']
    #print 'Allocate new repository: '+str(repo_id)
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
    if images:
        existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
        if existing_repo is None:
            return HTTPNotFound()
        return {"access": True}
    else:
        return Response('',status_code=204)

@view_config(route_name='api_library', renderer='json', request_method='DELETE')
def api_library_delete(request):
    print str(request)
    print "#Route: "+str(request.matchdict['image'])
    repo_id = None
    repo_id = request.matchdict['namespace'] + '/'+ request.matchdict['image']
    endpoints = request.registry.settings['dockerregistry']
    secret = request.registry.settings['secret_passphrase']
    username = None
    password= None
    if request.authorization:
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password):
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
    print str(request)
    print "#Route: "+str(request.matchdict['namespace'])+'/'+str(request.matchdict['image'])
    repo_id = request.matchdict['namespace'] + '/'+str(request.matchdict['image'])
    #images = json.loads(request.body, encoding=request.charset)
    #print str(images)
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
    print str(request)
    print "#Route: "+str(request.matchdict['repo'])
    images = json.loads(request.body, encoding=request.charset)
    print "Images: "+str(images)
    repo_id = None
    repo_id = request.matchdict['namespace'] + '/'+ request.matchdict['image']
    #print 'Allocate new repository: '+str(repo_id)
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
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if existing_repo is not None and images:
        request.registry.db_mongo['repository'].update({'id': repo_id}, {"$set":{'images': images}})
    else:
        repo = { 'id' : repo_id, 'images': images, 'user': username, 'pulls': 0, 'visible': False }
        request.registry.db_mongo['repository'].insert(repo)
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
    print "#Other Route: "+str(request.matchdict['api'])
    print str(request)
    return Response('OK')

'''
@view_config(route_name='api2_other', renderer='json')
def api2_other(request):
    print str(request.matchdict['api'])
    print str(request)
    return Response('OK')
'''

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

def user_can_push(username, repository, request):
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
        if existing_repo['user'] == username:
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
    print str(request)
    account = None
    try:
        account = request.params['account']
    except Exception:
        pass
    service = request.params['service']
    scope = None
    try:
        scope = request.params['scope']
        print "Scope: "+str(scope)
    except Exception:
        pass
    if request.authorization:
        # Login request
        (type, bearer) = request.authorization
        username, password = decode(bearer)
        if not valid_user(username, password):
            return HTTPForbidden()
        secret = None
        #with open('/root/shadock/id_ecdsa', 'r') as content_file:
        #    secret = load_pem_private_key(content_file.read().encode('utf-8'),
        #                                      password=None, backend=default_backend())
        private_key = None
        with open('/root/shadock/wildcard.genouest.org.key', 'r') as content_file:
            private_key = load_pem_private_key(content_file.read().encode('utf-8'),
                                              password=None, backend=default_backend())

        #cryptomodulus = None
        #cryptoexponent = None
        kk = None
        with open('/root/shadock/wildcard.genouest.org.key', 'r') as content_file:
            from Crypto.PublicKey import RSA
            kk  = RSA.importKey(content_file.read(), passphrase=None)
        #    pub = kk.publickey()
        #    cryptomodulus = pub.n
        #    cryptoexponent = pub.e

        #with open('/root/shadock/wildcard.genouest.org.key', 'r') as content_file:
        #    private_key = content_file.read().encode('utf-8')

        pub_key = None
        pem = None
        exponent = None
        modulus = None
        with open('/root/shadock/wildcard.genouest.org.crt', 'r') as content_file:
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
            #print "Modulus: "+str(modulus)
            #print "Exponent: "+str(exponent)
        der = None
        with open('/root/shadock/wildcard.genouest.org.der', 'rb') as content_file:
            der = content_file.read()


        rootder = None
        with open('/root/shadock/GandiStandardSSLCA2.der', 'rb') as content_file:
            rootder = content_file.read()

        #pub_key = secret.public_key()
        #curve = pub_key.public_numbers()
        #x = long_to_bytes(curve.x,32)
        #y = long_to_bytes(curve.y,32)
        #print str(x)+":"+str(y)
        #pem = pem.encode('utf-8')
        #print str(private_key)
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
                        #secret,  algorithm='ES256',
                        #headers={'jwk': {'kty': 'EC', 'crv': 'P-256',
                        #                  'x': base64.urlsafe_b64encode(x),
                        #                  'y': base64.urlsafe_b64encode(y)
                        #}}
                        private_key,  algorithm='RS256',
                        #headers={'x5c': [base64.b64encode(pem)], 'use': 'sig'})
                        headers={'jwk': {'kty': 'RSA', 'alg': 'RS256',
                                          #'n': base64.urlsafe_b64encode(struct.pack('256p',str(modulus))),
                                          #'e': base64.urlsafe_b64encode(struct.pack('3p',str(exponent))),
                                          'n': base64.urlsafe_b64encode(modulus),
                                          'e': base64.urlsafe_b64encode(exponent),
                                          'x5c': [base64.b64encode(der)]
                                          #'x5c': [base64.b64encode(der), base64.b64encode(rootder)]
                        }}
                        #headers={'kid': 'IJCY:YEVM:CNWT:3NDP:CWAA:SLAY:PKZ5:ZUVT:22OE:NU2Q:TXG7:TNOS'}
                        )
        ''' 
        pub_jwk = {'k': der }
        claims = {'iss': request.registry.settings['issuer'],
                        'sub': username,
                        'aud': service,
                        'access':[],
                        'nbf': int(time.time()),
                        'iat': int(time.time()),
                        'exp': int(time.time()) + 3600,
                        }
        jws = jose.sign(claims, pub_jwk, alg='RS256')
        jwt = jose.serialize_compact(jws)
        return {'token': jwt}
        '''
        #print pem
        #print str(base64.urlsafe_b64encode(str(exponent)))
        return {'token': token}
    return HTTPForbidden()


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
