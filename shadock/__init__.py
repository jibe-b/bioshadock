from pyramid.config import Configurator
from pyramid.renderers import JSON
from pyramid.events import BeforeRender
from pyramid_beaker import session_factory_from_settings



import sys
import json
import datetime
from pymongo import MongoClient
from bson import json_util
from bson.objectid import ObjectId

import redis
from elasticsearch import Elasticsearch
import logging
import os


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    config.include('pyramid_chameleon')
    social_providers = config.registry.settings['allow_auth'].split(',')
    if 'google' in social_providers:
        config.include('velruse.providers.google_oauth2')
        config.add_google_oauth2_login_from_settings()
    if 'github' in social_providers:
        config.include('velruse.providers.github')
        config.add_github_login_from_settings()
    config.add_subscriber(before_render, BeforeRender)

    my_session_factory = session_factory_from_settings(settings)
    config.set_session_factory(my_session_factory)

    mongo = MongoClient(config.registry.settings['mongo_url'])
    dbmongo = mongo['mydockerhub']
    config.registry.db_mongo = dbmongo

    r = redis.StrictRedis(host=config.registry.settings['redis_host'], port=int(config.registry.settings['redis_port']), db=0)
    config.registry.db_redis = r

    config.registry.admin = config.registry.settings['admin'].split(',')

    config.registry.es = Elasticsearch(config.registry.settings['elastic_host'].split(','))

    config.registry.ldap_server = None
    config.registry.con = None
    if config.registry.settings['use_ldap'] == '1':
        # Check if in ldap
        #import ldap
        from ldap3 import Server, Connection, AUTH_SIMPLE, STRATEGY_SYNC, STRATEGY_ASYNC_THREADED, SEARCH_SCOPE_WHOLE_SUBTREE, GET_ALL_INFO
        try:
            ldap_host = config.registry.settings['ldap.host']
            ldap_port = config.registry.settings['ldap.port']
            config.registry.ldap_server = Server(ldap_host, port=int(ldap_port), get_info=GET_ALL_INFO)
        except Exception as err:
            logging.error(str(err))
            sys.exit(1)


    config.add_static_view('static', 'static', cache_max_age=3600)

    runenv = "dist"
    if "BIOSHADOCK_ENV" in os.environ and os.environ["BIOSHADOCK_ENV"] == "dev":
        runenv = "dev"

    config.add_static_view('app', 'shadock:webapp/'+runenv+'/')
    config.add_route('home', '/')
    config.add_route('config', '/config')
    config.add_route('search', '/search')
    config.add_route('user_is_logged', '/user/logged')
    config.add_route('users', '/user')
    config.add_route('user_logout', '/user/logout')
    config.add_route('user_bind', '/user/bind')
    config.add_route('user', '/user/{id}')
    config.add_route('containers', '/container')
    config.add_route('containers_all', '/container/all')
    config.add_route('containers_latest', '/container/latest')
    config.add_route('containers_search', '/container/search')
    config.add_route('containers_new', '/container/new')
    config.add_route('container_manifest', '/container/manifest/*id')
    config.add_route('container_tags', '/container/tags/*id')
    config.add_route('container_dockerfile', '/container/dockerfile/*id')
    config.add_route('container_git', '/container/git/*id')
    config.add_route('container_tag', '/container/tag/*id')
    config.add_route('container_elixir', '/container/elixir/*id')
    config.add_route('container_metaelixir', '/container/metaelixir/*id')
    config.add_route('container', '/container/*id')
    config.add_route('api_users', '/v1/users/')
    config.add_route('api_library', '/v1/repositories/{image}/')
    config.add_route('api_library_auth', '/v1/repositories/{image}/auth')
    config.add_route('api_library_images', '/v1/repositories/{image}/images')
    config.add_route('api_repositories_images_get', '/v1/repositories/{namespace}/{image}/images')
    config.add_route('api_repositories_images_put', '/v1/repositories/{namespace}/{image}/images')
    config.add_route('api_repositories_images_layer_access', '/v1/repositories/{namespace}/{image}/layer/{id}/access')
    config.add_route('api_repositories', '/v1/repositories/{namespace}/{image}/')
    config.add_route('api_repositories_auth', '/v1/repositories/{namespace}/{image}/auth')
    config.add_route('api_ping', '/v1/_ping')
    config.add_route('api2_ping', '/v2/_ping')
    config.add_route('api2_token', '/v2/token/')
    config.add_route('api2_other', '/v2/*api')
    config.add_route('api_other', '/v1/*api')
    config.scan()

    json_renderer = JSON()
    def pymongo_adapter(obj, request):
        return json_util.default(obj)
    json_renderer.add_adapter(ObjectId, pymongo_adapter)
    json_renderer.add_adapter(datetime.datetime, pymongo_adapter)

    config.add_renderer('json', json_renderer)
    return config.make_wsgi_app()


def before_render(event):
    event["username"] = event['request'].authenticated_userid

