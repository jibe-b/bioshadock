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
import copy
import logging
import string
import random
import tempfile
import os
import subprocess
import bcrypt

import smtplib
from email.mime.text import MIMEText

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
import pymongo

from ldap3 import Server, Connection, AUTH_SIMPLE, STRATEGY_SYNC, STRATEGY_ASYNC_THREADED, SEARCH_SCOPE_WHOLE_SUBTREE, GET_ALL_INFO


from bioshadock_biotools.parser import Parser
from bioshadock_biotools.biotools import BioTools

from clair.clair import Clair

def notify_new_container_email(request, repo):
    if not request.registry.config['general']['mail']['smtp_host'] or not request.registry.config['general']['mail']['to']:
        logging.debug('No smtp or to email configuration, skipping mail notification')
        return
    to = request.registry.config['general']['mail']['to']
    subject = 'New container created: ' + str(repo['id'])
    message = 'New container: ' + str(repo['id'])
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = request.registry.config['general']['mail']['from']
    msg['To'] = request.registry.config['general']['mail']['to']
    try:
        s = smtplib.SMTP(request.registry.config['general']['mail']['smtp_host'], request.registry.config['general']['mail']['smtp_port'])
        if request.registry.config['general']['mail']['tls']:
            s.starttls()
        if request.registry.config['general']['mail']['smtp_user']:
            s.login(request.registry.config['general']['mail']['smtp_user'], request.registry.config['general']['mail']['smtp_password'])

        s.sendmail(msg['From'], [msg['To']], msg.as_string())
        s.quit()
    except Exception as e:
        logging.error('Email error: ' + str(e))

def build_container(request, build):
    request.registry.db_redis.hincrby('bioshadock:user:builds', build['user'], 1)
    request.registry.db_redis.rpush('bioshadock:builds:' + build['user'], dumps(build))

def is_admin(username, request):
    user = request.registry.db_mongo['users'].find_one({'id': username})
    if user is None:
        return False
    if user['role'] == 'admin':
        return True
    return False

def can_push_to_library(username, request):
    user = request.registry.db_mongo['users'].find_one({'id': username})
    if user is None:
        return False
    if user['role'] == 'admin' or user['role'] == 'editor':
        return True
    return False

def valid_user(username, password, request):
    if 'BIOSHADOCK_AUTH' in os.environ and os.environ['BIOSHADOCK_AUTH'] == 'fake':
        return True
    user = request.registry.db_mongo['users'].find_one({'id': username})
    if user is None or 'password' not in user:
        # If user logged via social, no password available, use apikey for authentication on API
        if user is not None and 'type' in user and user['type'] == 'social':
            if user['apikey'] and user['apikey'] == password:
                return True
        ldap_dn = request.registry.config['ldap']['dn']
        base_dn = 'ou=People,' + ldap_dn
        ldapfilter = "(&(|(uid=" + username + ")(mail=" + username + ")))"
        try:
            attrs = ['uid', 'mail']
            con = Connection(request.registry.ldap_server, auto_bind=True, client_strategy=STRATEGY_SYNC, check_names=True)
            con.search(base_dn, ldapfilter, SEARCH_SCOPE_WHOLE_SUBTREE, attributes=attrs)
            if con.response:
                user_dn= None
                user_id = None
                for r in con.response:
                    user_dn = str(r['dn'])
                    user_id = r['attributes']['uid']
                con.unbind()
                con = Connection(request.registry.ldap_server, auto_bind=True, read_only=True, client_strategy=STRATEGY_SYNC, user=user_dn, password=password, authentication=AUTH_SIMPLE, check_names=True)
                con.unbind()

            else:
                con.unbind()
                return False

            if user_dn is not None and user is None:
                role = 'contributor'
                if username in request.registry.admin:
                    role = 'admin'
                apikey = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(20))
                request.registry.db_mongo['users'].insert({'id': username,
                                                           'role': role,
                                                           'apikey': apikey,
                                                           'type': 'ldap'})

        except Exception as e:
            logging.error(str(e))
            return False
    else:
        print "local user"
        if bcrypt.hashpw(password.encode('utf-8'), user['password'].encode('utf-8')) == user['password']:
            return True
        else:
            return False
    return True


def is_logged(request):
    '''
    Check if user is logged, return user info or None
    '''
    if request.authorization is not None:
        try:
            (type, bearer) = request.authorization
            secret = request.registry.config['registry']['secret_passphrase']
            # If decode ok and not expired
            user = jwt.decode(bearer, secret, audience='urn:bioshadock/auth')
            return user['user']
        except Exception:
            return None
    return None

@view_config(route_name='users', renderer='json', request_method='GET')
def users(request):
    session_user = is_logged(request)
    if session_user is None:
        return HTTPForbidden('User not logged')
    users = request.registry.db_mongo['users'].find({})
    res = []
    for user in users:
        res.append(user)
    return res

@view_config(route_name='user', renderer='json', request_method='POST')
def user(request):
    session_user = is_logged(request)
    if session_user is None:
        return HTTPForbidden('User not logged')
    user = request.registry.db_mongo['users'].find_one({'id': request.matchdict['id']})
    if user is None:
        return HTTPNotFound()
    if not is_admin(session_user['id'], request):
        return HTTPForbidden()
    if session_user['id'] == user['id']:
        return HTTPForbidden()
    form = json.loads(request.body, encoding=request.charset)
    user['role'] = form['role']
    request.registry.db_mongo['users'].update({'id': user['id']},{'$set': {'role': user['role']}})
    return user

@view_config(route_name='config', renderer='json', request_method='GET')
def config(request):
    config = {
        'registry': request.registry.config['registry']['docker'],
        'service': request.registry.config['registry']['service'],
        'issuer': request.registry.config['registry']['issuer']
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
    token = None
    if form and 'token' in form:
        token = form['token']
    if token:
        secret = request.registry.config['registry']['secret_passphrase']
        user = jwt.decode(token, secret, audience='urn:bioshadock/auth')
        uid = user['user']['id']
        user = request.registry.db_mongo['users'].find_one({'id': uid})
        if user is not None and 'type' in user and user['type'] == 'ldap':
            return HTTPUnauthorized('Trying to connect with the id of an existing user')
        if user is None:
            role = 'visitor'
            apikey = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(20))
            request.registry.db_mongo['users'].insert({'id': uid,
                                                       'role': role,
                                                       'apikey': apikey,
                                                       'type': 'social'})

    else:
        if not valid_user(uid, password, request):
            return HTTPUnauthorized('Invalid credentials')
    user = request.registry.db_mongo['users'].find_one({'id': uid})
    if not user:
        return HTTPUnauthorized('Invalid credentials')
    secret = request.registry.config['registry']['secret_passphrase']
    del user['_id']
    token = jwt.encode({'user': user,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3600),
                        'aud': 'urn:bioshadock/auth'}, secret)
    return { 'user': user, 'token': token }


@view_config(route_name='search', renderer='json', request_method='GET')
def search_es(request):
    q = request.params['q']
    user = is_logged(request)

    conditions = []
    key = "_all"
    value = q
    if ":" in q:
        elts = q.split(":")
        key = 'meta.' + elts[0]
        value = elts[1]
    query = [ {"term": {key: value}}]
    if user is None:
        query.append({"term": {"visible": True}})
    else:
        conditions.append({"term": {"visible": True}})
        conditions.append({"term": {"user": user['id']}})
        conditions.append({"term": {"acl_push.members": user['id']}})
        conditions.append({"term": {"acl_pull.members": user['id']}})
    res = request.registry.es.search(
      index = "bioshadock",
      search_type = 'query_then_fetch',
      size = 1000,
      body = {
        "query" : { "filtered" : {  "filter" : { "bool" :
                      {"must": query, "should": conditions},
                  } } },

      })

    return res

@view_config(route_name='containers_latest', renderer='json', request_method='GET')
def containers_latest(request):
    repos = request.registry.db_mongo['repository'].find({'library': True},{'id': 1, 'description': 1}, sort=[('_id', pymongo.DESCENDING)], limit=20)
    library_containers = []
    for container in repos:
        library_containers.append(container)
    return library_containers

@view_config(route_name='containers_all', renderer='json', request_method='GET')
def containers_all(request):
    light = False
    if 'light' in request.params:
        light = True
    user = is_logged(request)
    if user is None or not is_admin(user['id'], request):
        #return HTTPForbidden()
        repos = request.registry.db_mongo['repository'].find({'visible': True})
    else:
        repos = request.registry.db_mongo['repository'].find()
    user_repos = []
    for repo in repos:
        if 'builds' in repo:
            del repo['builds']
        if 'Dockerfile' in repo['meta'] and repo['meta']['Dockerfile']:
            repo['meta']['Dockerfile'] = True
        else:
            repo['meta']['Dockerfile'] = False

        if light:
            if 'built' not in repo['meta']:
                repo['meta']['built'] = False
            if 'short_description' not in repo['meta']:
                repo['meta']['short_description'] = repo['meta']['description']
            if 'git' not in repo['meta']:
                repo['meta']['git'] = None
            user_repos.append({
                'id': repo['id'],
                'meta': {
                    'short_description': repo['meta']['short_description'],
                    'built': repo['meta']['built'],
                    'git': repo['meta']['git'],
                    'Dockerfile': repo['meta']['Dockerfile']
                },
                'user': repo['user'],
                'visible': repo['visible']
            })
        else:
            user_repos.append(repo)
    return user_repos

@view_config(route_name='builds', renderer='json', request_method='GET')
def builds(request):
    '''
    Get all builds for container, remove response log to limit size
    '''
    user = is_logged(request)
    if user is None:
        return HTTPForbidden()

    repo_id = '/'.join(request.matchdict['id'])
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if not repo['visible']:
        if user is None:
            return HTTPForbidden()
        if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()

    builds = request.registry.db_mongo['builds'].find({'id': repo_id}, {'response': 0})
    res = []
    for build in builds:
        res.append(build)
    return res

@view_config(route_name='build', renderer='json', request_method='GET')
def build(request):
    '''
    Get a build with complete response
    '''
    user = is_logged(request)
    if user is None:
        return HTTPForbidden()

    build_id = request.matchdict['id']
    build = request.registry.db_mongo['builds'].find_one({'_id': ObjectId(build_id)})
    repo_id = build['id']
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if user is None:
        return HTTPForbidden()
    if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
        return HTTPForbidden()

    return build



@view_config(route_name='containers', renderer='json', request_method='GET')
def containers(request):
    user = is_logged(request)
    if user is None:
        return HTTPForbidden()
    repos = request.registry.db_mongo['repository'].find({'$or': [{'user': user['id']}, {'acl_pull.members': user['id']}]})
    user_repos = []
    for repo in repos:
        if 'builds' in repo:
            del repo['builds']
        if 'Dockerfile' in repo['meta'] and repo['meta']['Dockerfile']:
            repo['meta']['Dockerfile'] = True
        else:
            repo['meta']['Dockerfile'] = False
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
        if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()

    form = json.loads(request.body, encoding=request.charset)
    token = form['token']
    tag = form['tag']
    http = urllib3.PoolManager()
    headers = {'Authorization': 'Bearer '+token,
                'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
    r = http.request('GET', request.registry.config['registry']['docker']+'/v2/'+repo_id+'/manifests/'+tag, headers=headers)
    if r.status != 200:
        return Response('could not get the manifest', status_code = r.status)
    res = json.loads(r.data)
    docker_content_digest = None
    if 'Docker-Content-Digest' in r.headers:
        docker_content_digest = r.headers['Docker-Content-Digest']
    else:
        docker_content_digest = res['manifests'][0]['digest']
    res['Docker-Content-Digest'] = docker_content_digest
    return res


@view_config(route_name='container_metaelixir', renderer='json')
def container_metaelixir(request):
    repo_id = '/'.join(request.matchdict['id'])

    http = urllib3.PoolManager()
    r = http.request('GET', request.registry.config['elixir']['biotools_url']+'/api/tool/'+repo_id)
    if r.status != 200:
        return Response('could not get the metadata', status_code = r.status)
    return json.loads(r.data)


@view_config(route_name='container_elixir', renderer='json')
def container_elixir(request):
    '''
    Update elixir from a container Dockerfile

    /container/elixir/x/y/z
    '''
    if not request.registry.config['elixir']['script']:
        return HTTPForbidden('Not configured for Elixir updates')
    user = is_logged(request)
    if user is None:
        try:
            apikey = request.params['apikey']
            user = request.registry.db_mongo['users'].find_one({'apikey': apikey})
            if user is None:
                return HTTPForbidden()
        except Exception:
            return HTTPForbidden()
    repo_id = '/'.join(request.matchdict['id'])
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if not repo['visible']:
        if user is None:
            return HTTPForbidden()
        if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()
    dockerFile = repo['meta']['Dockerfile']
    if dockerFile is None or not dockerFile:
        return HTTPNotFound('No Dockerfile available')
    (tmpfh, tmpfilepath) = tempfile.mkstemp(prefix='elixir')
    tmpfile = open(tmpfilepath, 'w')
    tmpfile.write(dockerFile)
    tmpfile.close()

    (tmpfh, tmpxmlpath) = tempfile.mkstemp(prefix='elixir', suffix='.xml')

    softname = repo_id.split('/')[-1]
    resource = None

    try:
        parser = Parser(tmpfilepath)
        templFile = request.registry.config['elixir']['template']
        if not templFile or not os.path.exists(templFile):
            return HTTPForbidden('Configuration error, missing template.xml')
        parser.parse(templFile, tmpxmlpath)
        username = request.registry.config['elixir']['login']
        password = request.registry.config['elixir']['password']
        biotools = BioTools({
            act: 'update',
            resFile: tmpxmlpath,
            xmlTransportFormat: True
        })
        resource = biotools.get_resource(options)
        jsonResp=biotools.execLoginCmd(username, password)
        if 'token' not in jsonResp:
            return HTTPForbidden('Could not authentify against bio.tools')
        jsonResp=biotools.execRegisterOrUpdateCmd(token, tmpxmlpath, "application/xml")

    except Exception as e:
        logging.error("Elixir bio.tools call error: "+str(e))
        return {'msg': 'An error occured, please contact support team'}

    os.remove(tmpfilepath)
    os.remove(tmpxmlpath)

    affiliation = request.registry.config['elixir']['affiliation']
    elixir_name = affiliation+'/'+softname
    if 'name' in resource and resource['name']:
        elixir_name = affiliation+'/'+resource['name']

    request.registry.db_mongo['repository'].update({'_id': repo['_id']},{'$set': {'meta.elixir': elixir_name}})
    return {'msg': 'Request executed', 'elixir': elixir_name}


@view_config(route_name='container_tag', renderer='json')
def container_tag(request):
    '''
    Tags a container

    /container/tag/x/y/z/:tagid
    '''
    user = is_logged(request)

    if user is None:
        try:
            apikey = request.params['apikey']
            user = request.registry.db_mongo['users'].find_one({'apikey': apikey})
            if user is None:
                return HTTPForbidden()
        except Exception:
            return HTTPForbidden()

    repo_elts = list(request.matchdict['id'])
    tag = repo_elts.pop()
    repo_id = '/'.join(repo_elts)

    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if not repo['visible']:
        if user is None:
            return HTTPForbidden()
        if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()

    user_id = user['id']

    container = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if 'git' not in container['meta'] and not container['meta']['Dockerfile']:
        return HTTPForbidden()

    build = request.registry.db_mongo['builds'].insert({'id': repo_id,
                                                        'progress': 'waiting'})

    newbuild = {
        'id': repo_id,
        'build': str(build),
        'date': datetime.datetime.now(),
        'dockerfile': container['meta']['Dockerfile'],
        'git': None,
        'cwl_path': container['meta']['cwl_path'],
        'user': user_id,
        'tag': tag
    }
    if 'git' in container['meta']:
        newbuild['git'] = container['meta']['git']

    build_container(request, newbuild)
    # request.registry.db_redis.rpush('bioshadock:builds', dumps(newbuild))
    return {'repo': repo_id, 'tag': tag}


@view_config(route_name='container_git', renderer='json')
def container_git(request):
    '''
    trigger for a git rebuild, must container a Dockerfile in git repo or in container def
    '''
    user = is_logged(request)

    if user is None:
        try:
            apikey = request.params['apikey']
            user = request.registry.db_mongo['users'].find_one({'apikey': apikey})
            if user is None:
                return HTTPForbidden()
        except Exception:
            return HTTPForbidden()
    repo_id = '/'.join(request.matchdict['id'])

    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if not repo['visible']:
        if user is None:
            return HTTPForbidden()
        if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()

    user_id = 'anonymous'
    if user is not None:
        user_id = user['id']

    container = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if 'git' not in container['meta']:
        return HTTPForbidden()

    build = request.registry.db_mongo['builds'].insert({'id': repo_id,
                                                        'progress': 'waiting'})

    newbuild = {
        'id': repo_id,
        'build': str(build),
        'date': datetime.datetime.now(),
        'dockerfile': container['meta']['Dockerfile'],
        'git': container['meta']['git'],
        'cwl_path': container['meta']['cwl_path'],
        'user': user_id
    }
    build_container(request, newbuild)
    # request.registry.db_redis.rpush('bioshadock:builds', dumps(newbuild))
    return {}


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
        if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()
    form = json.loads(request.body, encoding=request.charset)
    dockerfile = form['dockerfile']
    if 'git' not in form:
        form['git'] = None
    request.registry.db_mongo['repository'].update({'id': repo_id},{'$set': {'meta.Dockerfile': dockerfile}})

    build = request.registry.db_mongo['builds'].insert({'id': repo_id,
                                                        'progress': 'waiting'})
    cwl_path = None
    if 'cwl_path' in repo['meta']:
        cwl_path = repo['meta']['cwl_path']

    newbuild = {
        'id': repo_id,
        'build': str(build),
        'date': datetime.datetime.now(),
        'dockerfile': dockerfile,
        'git': form['git'],
        'user': user['id'],
        'cwl_path': cwl_path
    }
    build_container(request, newbuild)
    # request.registry.db_redis.rpush('bioshadock:builds', dumps(newbuild))
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
        if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()

    form = json.loads(request.body, encoding=request.charset)
    token = form['token']
    http = urllib3.PoolManager()
    headers = {'Authorization': 'Bearer '+token}
    r = http.request('GET', request.registry.config['registry']['service']+'/v2/'+repo_id+'/tags/list', headers=headers)
    if r.status != 200:
        return Response('could not get the manifest', status_code = r.status)
    return json.loads(r.data)


@view_config(route_name='container', renderer='json', request_method='DELETE')
def container_delete(request):
    user = is_logged(request)
    repo_id = '/'.join(request.matchdict['id'])
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if user is None:
        return HTTPForbidden()
    if repo is None:
        return HTTPNotFound()
    if not (is_admin(user['id'], request) or repo['user'] == user['id'] or user['id'] in repo['acl_push']['members']):
        return HTTPForbidden()
    # Get digest from manifest Docker-Content-Digest sha256:95b09cb5b7cd38d73a7dc9618c34148559cf1ed3a0066c85d37e1d6cf4fb9004
    # Send DELETE request DELETE /v2/<name>/manifests/<reference>
    # Commented, removing image seems to remove some layers used by other image
    # Delete from database but keep in ever growing registry
    '''
    form = json.loads(request.body, encoding=request.charset)
    token = form['token']
    tag = 'latest'
    if 'tag' in form:
        tag = form['tag']
    http = urllib3.PoolManager()
    headers = {'Authorization': 'Bearer '+token,
                'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
    r = http.request('GET', request.registry.config['registry']['docker']+'/v2/'+repo_id+'/manifests/'+tag, headers=headers)
    if r.status == 404:
        logging.warn('Registry could not get the manifest '+repo_id)
    else:
        res = json.loads(r.data)
        docker_content_digest = None
        if 'Docker-Content-Digest' in r.headers:
            docker_content_digest = r.headers['Docker-Content-Digest']
        else:
            docker_content_digest = res['manifests'][0]['digest']
        r = http.request('DELETE', request.registry.config['registry']['docker']+'/v2/'+repo_id+'/manifests/'+docker_content_digest, headers=headers)
        if r.status != 202:
            logging.error('Could not find or delete image ' + repo_id + 'in registry')
    '''
    request.registry.db_mongo['repository'].remove({'id': repo_id})
    request.registry.db_mongo['builds'].remove({'id': repo_id})
    request.registry.db_mongo['versions'].remove({'repo': repo_id})
    request.registry.es.delete(index="bioshadock", doc_type='container', id=repo_id)
    return repo

@view_config(route_name='container', renderer='json', request_method='POST')
def container_update(request):
    user = is_logged(request)
    repo_id = '/'.join(request.matchdict['id'])
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if user is None:
        return HTTPForbidden()
    if repo is None:
        return HTTPNotFound()
    if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_push']['members']:
        return HTTPForbidden()
    form = json.loads(request.body, encoding=request.charset)
    if 'git' not in form['meta']:
        form['meta']['git'] = None
    if 'elixir' not in form['meta']:
        form['meta']['elixir'] = None
    if 'cwl_path' not in form['meta']:
        form['meta']['cwl_path'] = None

    updates = {
        'acl_push.members': form['acl_push']['members'],
        'acl_pull.members': form['acl_pull']['members'],
        'meta.description': form['meta']['description'],
        'meta.short_description': form['meta']['short_description'],
        'meta.tags': form['meta']['tags'],
        'meta.terms': form['meta']['terms'],
        'meta.git': form['meta']['git'],
        'meta.elixir': form['meta']['elixir'],
        'meta.cwl_path': form['meta']['cwl_path'],
        'visible': form['visible']
    }
    repo['acl_push']['members'] = form['acl_push']['members']
    repo['acl_pull']['members'] = form['acl_pull']['members']
    repo['meta']['description'] = form['meta']['description']
    repo['meta']['tags'] = form['meta']['tags']
    repo['meta']['terms'] = form['meta']['terms']
    repo['meta']['cwl_path'] = form['meta']['cwl_path']
    repo['visible'] = form['visible']
    if is_admin(user['id'], request) or repo['user'] == user['id'] or user['id'] in repo['acl_push']['members']:
        repo['user_can_push'] = True
    else:
        repo['user_can_push'] = False
    request.registry.db_mongo['repository'].update({'id': repo_id}, {'$set': updates})
    es_repo = copy.deepcopy(repo)
    del es_repo['_id']
    del es_repo['builds']
    request.registry.es.index(index="bioshadock", doc_type='container', id=repo_id, body=es_repo)
    return repo


@view_config(route_name='clair_notification', renderer='json', request_method='POST')
def clair_notification(request):
    '''
    Receive a Clair notification about an update. Simply delete notification, no handling for the moment
    '''
    form = json.loads(request.body, encoding=request.charset)
    notif = form['Notification']['Name']
    '''
    page = 1
    limit = 100
    # Get notification
    loop = True
    while loop:
        r = http.request('GET', equest.registry.settings['clair.host']+'/v1/notification/'+notif+'?page='+str(page)+'&limit='+str(limit))
        if r.status != 200:
                loop = False
        res = json.loads(r.data)
        layers = res['Notification']['New']['LayersIntroducingVulnerability']
        for layer in layers:
            # Find repo using layer and udpate notifications
        page += 1
    '''
    # Mark as read
    http = urllib3.PoolManager()
    http.request('DELETE', request.registry.config['clair']['host']+'/v1/notification/'+notif)
    return {}


@view_config(route_name='container_vulnerabilities', renderer='json', request_method='GET')
def container_vulnerabilities(request):
    user = is_logged(request)
    repo_id = '/'.join(request.matchdict['id'])
    repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
    if repo is None:
        return HTTPNotFound()
    if not repo['visible']:
        if user is None:
            return HTTPForbidden()
        if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()
    # Get vulnerabilities from Clair
    if request.registry.config['clair']['use'] != 1:
        return HTTPForbidden()
    cfg = {
        'clair.host': request.registry.config['clair']['host'],
        'docker.connect': request.registry.config['services']['docker']['connect']

    }
    image_vulnerabilities = Clair(cfg)
    version = None
    try:
        version = request.params['version'].replace('.', '_')
    except Exception:
        pass
    logging.debug('Search vulnerabilities for '+repo_id+':'+str(version))
    if version is not None:
        if 'version' in repo['meta'] and version in repo['meta']['version']:
            layers = repo['meta']['version'][version]['layers']
        else:
            return HTTPNotFound()
    if version is None:
        if 'layers' not in repo['meta'] or not repo['meta']['layers']:
            return HTTPNotFound()
        else:
            layers = repo['meta']['layers']

    return image_vulnerabilities.get_layers_vulnerabilities(layers)


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
        if not is_admin(user['id'], request) and repo['user'] != user['id'] and user['id'] not in repo['acl_pull']['members']:
            return HTTPForbidden()
    if user and (is_admin(user['id'], request) or repo['user'] == user['id'] or user['id'] in repo['acl_push']['members']):
        repo['user_can_push'] = True
    else:
        repo['user_can_push'] = False
    return repo

@view_config(route_name='containers_new', renderer='json', request_method='POST')
def containers_new(request):
    user = is_logged(request)
    if user is None:
        return HTTPForbidden()
    form = json.loads(request.body, encoding=request.charset)
    if 'git' not in form or not form['git']:
        form['git'] = None
    repo_id = form['name']
    repo_name = repo_id.split('/')
    if len(repo_name) == 1:
        return HTTPForbidden("Invalid repository name, must match X/Y")
    if user_can_push(user['id'], repo_id, request):
        request.registry.db_mongo['repository'].update({'id': repo_id},
                        {'$set': {'meta.short_description': form['description'],
                                  'meta.description': '',
                                  'meta.Dockerfile': form['dockerfile'],
                                  'meta.git': form['git'],
                                  'meta.cwl_path': None,
                                  'visible': form['visible'] in ['true', 1]}
                        })

        build = request.registry.db_mongo['builds'].insert({'id': repo_id,
                                                            'progress': 'waiting'})
        newbuild = {
            'id': repo_id,
            'build': str(build),
            'date': datetime.datetime.now(),
            'dockerfile': form['dockerfile'],
            'git': form['git'],
            'user': user['id'],
            'cwl_path': None
        }
        build_container(request, newbuild)
        # request.registry.db_redis.rpush('bioshadock:builds', dumps(newbuild))
        repo = request.registry.db_mongo['repository'].find_one({'id': repo_id})
        es_repo = copy.deepcopy(repo)
        del es_repo['_id']
        del es_repo['builds']
        res = request.registry.es.index(index="bioshadock", doc_type='container', id=repo_id, body=es_repo)
        return repo
    else:
        return HTTPForbidden()

@view_config(route_name='containers_search', renderer='json', request_method='POST')
def containers_search(request):
    form = json.loads(request.body, encoding=request.charset)
    search = form['search']
    user = is_logged(request)
    regx = re.compile(search, re.IGNORECASE)
    if user is None:
            repos = request.registry.db_mongo['repository'].find({'visible': True, 'id': regx})
    else:
        repos = request.registry.db_mongo['repository'].find({'$or': [{'visible': True}, {'user': user['id']}, {'acl_pull.members': user['id']}], 'id': regx})
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
    #print str(request)
    repo_id = str(request.matchdict['namespace'])+'/'+str(request.matchdict['image'])
    secret = request.registry.config['registry']['secret_passphrase']
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
    endpoints = request.registry.config['registry']['docker']
    secret = request.registry.config['registry']['secret_passphrase']
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
    endpoints = request.registry.config['docker']['registry']
    secret = request.registry.config['registry']['secret_passphrase']
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
    endpoints = request.registry.config['registry']['docker']
    secret = request.registry.config['registry']['secret_passphrase']
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
    endpoints = request.registry.config['registry']['docker']
    secret = request.registry.config['registry']['secret_passphrase']
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
    secret = request.registry.config['registry']['secret_passphrase']
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
    secret = request.registry.config['registry']['secret_passphrase']
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
    endpoints = request.registry.config['registry']['docker']
    secret = request.registry.config['registry']['secret_passphrase']
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
    endpoints = request.registry.config['registry']['docker']
    secret = request.registry.config['registry']['secret_passphrase']
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
    secret = request.registry.config['registry']['secret_passphrase']
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
    endpoints = request.registry.config['registry']['docker']
    secret = request.registry.config['registry']['secret_passphrase']
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


def user_can_delete(username, repository, request):
    user_repo = repository
    repos = repository.split('/')
    #if len(repos) == 1:
    #    user_repo = 'library/'+repository
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': user_repo})
    if existing_repo is not None:
        if existing_repo['user'] == username or is_admin(username, request):
            return True
        else:
            return False
    else:
        return False

def user_can_push(username, repository, request):
    if username == 'anonymous':
        return False
    user_repo = repository
    is_library = False
    repos = repository.split('/')
    if len(repos) == 1:
        return False
    if repos[0] == 'library':
        if not can_push_to_library(username, request):
            return False
        #user_repo = 'library/'+repository
        is_library = True
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': user_repo})
    if existing_repo is not None:
        if existing_repo['user'] == username or username in existing_repo['acl_push']['members'] or username in request.registry.admin:
            return True
        else:
            return False
    else:
        user_db = request.registry.db_mongo['users'].find_one({'id': username})
        if user_db is None:
            return False
        else:
            # Contributors can push only is specified
            if user_db['role'] == 'contributor' and request.registry.config['general']['contributor_can_push'] != 1:
                return False
            # Visitors cannot push
            if user_db['role'] == 'visitor':
                return False
        if not is_library or (is_library and can_push_to_library(username, request)):
            repo = { 'id' : user_repo,
                     'user': username,
                     'pulls': 0,
                     'visible': True,
                     'library': is_library,
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
            notify_new_container_email(request, repo)
            es_repo = copy.deepcopy(repo)
            del es_repo['_id']
            del es_repo['builds']
            res = request.registry.es.index(index="bioshadock", doc_type='container', id=user_repo, body=es_repo)
            return True
        else:
            return False

def user_can_pull(username, repository, request):
    user_repo = repository
    repos = repository.split('/')
    #if len(repos) == 1:
    #    user_repo = 'library/'+repository
    existing_repo = request.registry.db_mongo['repository'].find_one({'id': user_repo})
    if existing_repo is not None:
        if existing_repo['user'] == username or username in existing_repo['acl_pull']['members'] or username in request.registry.admin:
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
    scopes = None
    try:
        #scope = request.params['scope']
        scopes = request.GET.getall('scope')
    except Exception:
        pass

    if request.authorization or request.authorization is None:
        # Login request
        if request.authorization is None:
            account = 'anonymous'
        if account != 'anonymous' and not is_logged(request):
            (bearer_type, bearer) = request.authorization
            username, password = decode(bearer)
            if username == 'anonymous':
                username = account
            elif not valid_user(username, password, request):
                logging.error("User authentication failure")
                return HTTPForbidden()
        else:
            username = account
        secret = None

        private_key = None
        passphrase = None
        if request.registry.config['certs']['private_key_passphrase']:
            passphrase = request.registry.config['certs']['private_key_passphrase']
        with open(request.registry.config['certs']['private_key'], 'r') as content_file:
            private_key = load_pem_private_key(content_file.read().encode('utf-8'),
                                              password=passphrase, backend=default_backend())


        pub_key = None
        pem = None
        exponent = None
        modulus = None
        with open(request.registry.config['certs']['public_key'], 'r') as content_file:
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
        with open(request.registry.config['certs']['cacert_der'], 'rb') as content_file:
            der = content_file.read()


        access = []
        if scopes is not None:
            access = []
            for scope in scopes:
                scope = scope.split(':')
                repo_type = scope[0]
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
                access.append({
                  "type": repo_type,
                  "name": repository,
                  "actions": allowed_actions
                })

        claims = {'iss': request.registry.config['registry']['issuer'],
                        'sub': username,
                        'aud': service,
                        'access': access,
                        #'nbf': datetime.datetime.utcnow(),
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
    user_id = None
    existing_user = request.registry.db_mongo['users'].find_one({'id': user_id})
    if not existing_user:
        return HTTPForbidden("You must register first")
    return Response("User Created", status_code=201)

@view_config(route_name='ga4gh_tools_query', renderer='json', request_method='GET')
def ga4gh_tools_query(request):
    return HTTPNotFound()

@view_config(route_name='ga4gh_tool_descriptor', renderer='json', request_method='GET')
def ga4gh_tool_descriptor(request):
    if 'format' in request.params and request.params['format'].lower() != 'cwl':
        return HTTPNotFound()
    repo_id = request.matchdict['id']
    elts = repo_id.split('@')
    repo_id = elts[0]
    repo = request.registry.db_mongo['repository'].find_one({'_id': ObjectId(repo_id), 'visible': True})
    if 'cwl' not in repo['meta'] or not repo['meta']['cwl']:
        return HTTPNotFound()
    return { 'descriptor': repo['meta']['cwl'] }

@view_config(route_name='ga4gh_tool_dockerfile', renderer='json', request_method='GET')
def ga4gh_tool_dockerfile(request):
    repo_id = request.matchdict['id']
    elts = repo_id.split('@')
    repo_id = elts[0]
    repo = request.registry.db_mongo['repository'].find_one({'_id': ObjectId(repo_id), 'visible': True})
    if 'Dockerfile' not in repo['meta'] or not repo['meta']['Dockerfile']:
        return HTTPNotFound()
    return { 'dockerfile': repo['meta']['Dockerfile'] }

'''
    config.add_route('ga4gh_tools', '/api/ga4gh/v1/tools')
    config.add_route('ga4gh_tools_id', '/api/ga4gh/v1/tools/{id}')
    config.add_route('ga4gh_tools_id_versions', '/api/ga4gh/v1/tools/{id}/versions')
    config.add_route('ga4gh_tools_id_version', '/api/ga4gh/v1/tools/{id}/versions/{versionid}')
    config.add_route('ga4gh_tools_id_version_descriptor', '/api/ga4gh/v1/tools/{id}/versions/{versionid}/{type}/descriptor')
    config.add_route('ga4gh_tools_id_version_descriptor_file_relative_path', '/api/ga4gh/v1/tools/{id}/versions/{versionid}/{type}/descriptor/{relativepath}')
    config.add_route('ga4gh_tools_id_version_dockerfile', '/api/ga4gh/v1/tools/{id}/versions/{versionid}/dockerfile')
    config.add_route('ga4gh_metadata', '/api/ga4gh/v1/metadata')
    config.add_route('ga4gh_tool_classes', '/api/ga4gh/v1/tool-classes')
'''


@view_config(route_name='ga4gh_metadata', renderer='json', request_method='GET')
def ga4gh_metadata(request):
    return {
        'version': '1.0',
        'api-version': '1.0',
        'country': 'FRA',
        'friendly-name': 'bioshadock'
    }

@view_config(route_name='ga4gh_tools_id', renderer='json', request_method='GET')
def ga4gh_tools_id(request):
    repo_id = request.matchdict['id']
    elts = repo_id.split('@')
    repo_id = elts[0]
    repo = request.registry.db_mongo['repository'].find_one({'_id': ObjectId(repo_id), 'visible': True})
    if not repo:
        return HTTPNotFound()
    repo_versions = request.registry.db_mongo['versions'].find({'repo': repo['id']})
    if not repo_versions:
        return HTTPNotFound()
    toolname = repo['id'].split('/')[-1:][0]
    tool = {
            'url': 'https://'+request.registry.config['registry']['issuer']+ '/app/#/container/' + repo['id'],
            'id': str(repo['_id'])+'@'+request.registry.config['registry']['service'],
            'organization': request.registry.config['registry']['service'],
            'toolname': toolname,
            'tooltype': {},
            'description': repo['meta']['description'],
            'author': repo['user'],
            'meta-version': 'latest',
            'versions': []
        }
    # Versions
    versions = []
    # Versions
    for repo_version in repo_versions:
        version = {
            'id': repo_version['version'],
            'name': repo_version['version'],
            'meta-version': 'latest',
            'url': 'https://'+request.registry.config['registry']['issuer']+ '/app/#/container/' + repo['id'],
            'image': request.registry.config['registry']['service'] + '/' + repo['id'] + ':' + repo_version['version'],
            'descriptor-type': [],
            'dockerfile': False
        }
        if repo_version['cwl']:
            version['descriptor-type'] = ['CWL']
        if repo_version['dockerfile']:
                version['dockerfile'] = {'dockerfile': True}
        versions.append(version)
    tool['versions'] = versions
    return tool

@view_config(route_name='ga4gh_tools_id_versions', renderer='json', request_method='GET')
def ga4gh_tools_id_versions(request):
    repo_id = request.matchdict['id']
    elts = repo_id.split('@')
    repo_id = elts[0]
    repo = request.registry.db_mongo['repository'].find_one({'_id': ObjectId(repo_id), 'visible': True})
    if not repo:
        return HTTPNotFound()
    repo_versions = request.registry.db_mongo['versions'].find({'repo': repo['id']})
    if not repo_versions:
        return HTTPNotFound()

    versions = []
    # Versions
    for repo_version in repo_versions:
        version = {
            'id': repo_version['version'],
            'name': repo_version['version'],
            'meta-version': 'latest',
            'url': 'https://'+request.registry.config['registry']['issuer']+ '/app/#/container/' + repo['id'],
            'image': request.registry.config['registry']['service'] + '/' + repo['id'] + ':' + repo_version['version'],
            'descriptor-type': [],
            'dockerfile': False
        }
        if repo_version['cwl']:
            version['descriptor-type'] = ['CWL']
        if repo_version['dockerfile']:
                version['dockerfile'] = {'dockerfile': True}
        versions.append(version)
    return versions

@view_config(route_name='ga4gh_tools_id_version', renderer='json', request_method='GET')
def ga4gh_tools_id_version(request):
    repo_id = request.matchdict['id']
    elts = repo_id.split('@')
    repo_id = elts[0]
    repo_version_id = request.matchdict['versionid']
    repo = request.registry.db_mongo['repository'].find_one({'_id': ObjectId(repo_id), 'visible': True})
    if not repo:
        return HTTPNotFound()
    repo_version = request.registry.db_mongo['versions'].find_one({'repo': repo['id'], 'version': repo_version_id})
    if not repo_version:
        return HTTPNotFound()

    version = {
        'id': repo_version['version'],
        'name': repo_version['version'],
        'meta-version': 'latest',
        'url': 'https://'+request.registry.config['registry']['issuer']+ '/app/#/container/' + repo['id'],
        'image': request.registry.config['registry']['service'] + '/' + repo['id'] + ':' + repo_version['version'],
        'descriptor-type': [],
        'dockerfile': False
    }
    if repo_version['cwl']:
        version['descriptor-type'] = ['CWL']
    if repo_version['dockerfile']:
            version['dockerfile'] = {'dockerfile': True}
    return version

@view_config(route_name='ga4gh_tools_id_version_descriptor', renderer='json', request_method='GET')
def ga4gh_tools_id_version_descriptor(request):
    if request.matchdict['type'] not in ['CWL', 'plain-CWL']:
        return HTTPNotFound()
    repo_id = request.matchdict['id']
    repo_version = request.matchdict['versionid']
    elts = repo_id.split('@')
    repo_id = elts[0]
    repo = request.registry.db_mongo['repository'].find_one({'_id': ObjectId(repo_id), 'visible': True})
    if not repo:
        return HTTPForbidden()
    repo_version = request.registry.db_mongo['versions'].find_one({'repo': repo['id'], 'version': repo_version})
    if not repo_version:
        return HTTPNotFound()

    if not repo_version['cwl']:
        return HTTPNotFound()
    return { 'type': 'CWL', 'descriptor': repo_version['cwl'] }

@view_config(route_name='ga4gh_tools_id_version_descriptor_file_relative_path', renderer='json', request_method='GET')
def ga4gh_tools_id_version_descriptor_file_relative_path(request):
    return HTTPNotFound()

@view_config(route_name='ga4gh_tools_id_version_dockerfile', renderer='json', request_method='GET')
def ga4gh_tools_id_version_dockerfile(request):
    repo_id = request.matchdict['id']
    repo_version = request.matchdict['versionid']
    elts = repo_id.split('@')
    repo_id = elts[0]
    repo = request.registry.db_mongo['repository'].find_one({'_id': ObjectId(repo_id), 'visible': True})
    if not repo:
        return HTTPNotFound()
    repo_version = request.registry.db_mongo['versions'].find_one({'repo': repo['id'], 'version': repo_version})
    if not repo_version:
        return HTTPNotFound()

    if not repo_version['dockerfile']:
        return HTTPNotFound()
    return { 'dockerfile': repo_version['dockerfile'] }


@view_config(route_name='ga4gh_tool_classes', renderer='json', request_method='GET')
def ga4gh_tool_classes(request):
    return HTTPNotFound()

@view_config(route_name='ga4gh_tools', renderer='json', request_method='GET')
def ga4gh_tools(request):
    repos = request.registry.db_mongo['repository'].find({'visible': True})
    tools = []
    offset= 0
    if 'offset' in request.params:
        offset = int(request.params['offset'])
    limit = -1
    if 'limit' in request.params:
        limit = int(request.params['limit'])
    index = 0
    for repo in repos:
        toolname = repo['id'].split('/')[-1:][0]
        if 'cwl' not in repo['meta']:
            repo['meta']['cwl'] = None
        if 'id' in request.params:
            if request.params['id'] != str(repo['_id'])+'@'+request.registry.config['registry']['service']:
                continue
        if 'registry' in request.params:
            if request.params['registry'] != request.registry.config['registry']['service']:
                return []
        if 'organization' in request.params:
            if request.params['organization'] != request.registry.config['registry']['service']:
                return []
        if 'name' in request.params:
            if request.params['name'] != repo['id']:
                continue
        if 'toolname' in request.params:
            if request.params['toolname'] != toolname and request.params['toolname'] not in repo['meta']['tags']:
                continue
        if 'description' in request.params:
            if request.params['description'] not in repo['meta']['description']:
                continue
        if 'author' in request.params:
            if request.params['author'] != repo['user']:
                continue
        tool = {
            'url': 'https://'+request.registry.config['registry']['issuer']+ '/app/#/container/' + repo['id'],
            'id': str(repo['_id'])+'@'+request.registry.config['registry']['service'],
            'organization': request.registry.config['registry']['service'],
            'toolname': toolname,
            'tooltype': {},
            'description': repo['meta']['description'],
            'author': repo['user'],
            'meta-version': 'latest',
            'versions': []
        }
        # Versions
        if 'docker_tags' in repo['meta']:
            for docker_tag in repo['meta']['docker_tags']:
                if 'tag' not in repo['meta']['docker_tags'][docker_tag]:
                    repo['meta']['docker_tags'][docker_tag]['tag'] = 'latest'
                version = {
                    'id': repo['meta']['docker_tags'][docker_tag]['tag'],
                    'name': repo['meta']['docker_tags'][docker_tag]['tag'],
                    'meta-version': 'latest',
                    'url': 'https://'+request.registry.config['registry']['issuer']+ '/app/#/container/' + repo['id'],
                    'image': request.registry.config['registry']['service'] + '/' + repo['id'] + ':' + repo['meta']['docker_tags'][docker_tag]['tag'],
                    'descriptor-type': [],
                    'dockerfile': False
                }

                #repo_version = request.registry.db_mongo['versions'].find_one({'repo': repo['id'], 'version': repo['meta']['docker_tags'][docker_tag]['tag']})
                if 'cwl_path' in repo['meta'] and repo['meta']['cwl_path']:
                    version['descriptor-type'] = ['CWL']
                if repo['meta']['Dockerfile']:
                    version['dockerfile'] = {'dockerfile': True}
                tool['versions'].append(version)

        if limit == -1 or index < limit:
            if index >= offset and tool['versions']:
                tools.append(tool)
                index += 1
        if limit >= 0 and index >= limit:
            break

    return tools

@view_config(route_name='home', renderer='json')
def my_view(request):
    if 'BIOSHADOCK_INSECURE' in os.environ:
        return HTTPFound(request.static_path('shadock:webapp/'+request.registry.runenv+'/'))
    if request.scheme == "http":
        return HTTPFound("https://" + request.host + "/" + request.static_path('shadock:webapp/'+request.registry.runenv+'/'))
    return HTTPFound(request.static_path('shadock:webapp/'+request.registry.runenv+'/'))

@view_config(
    context='velruse.AuthenticationComplete',
)
def login_complete_view(request):
    context = request.context
    user_id = None
    if context.profile['preferredUsername']:
        user_id = context.profile['preferredUsername']
    else:
        user_id = context.profile['accounts'][0]['username']
    result = {
        'id': user_id,
        'provider_type': context.provider_type,
        'provider_name': context.provider_name,
        'profile': context.profile,
        'credentials': context.credentials,
    }
    secret = request.registry.config['registry']['secret_passphrase']
    token = jwt.encode({'user': result,
                        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=36000),
                        'aud': 'urn:bioshadock/auth'}, secret)
    return HTTPFound(request.static_url('shadock:webapp/dist/')+"index.html#login?token="+token)
