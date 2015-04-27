from pyramid.config import Configurator

from pymongo import MongoClient
from bson import json_util
from bson.objectid import ObjectId



def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    config.include('pyramid_chameleon')

    mongo = MongoClient('mongodb://localhost:27017/')
    dbmongo = mongo['mydockerhub']
    config.registry.db_mongo = dbmongo
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.add_route('home', '/')
    config.add_route('api_users', '/v1/users/')
    config.add_route('api_repositories', '/v1/repositories/*repo')
    config.add_route('api_ping', '/v1/_ping')
    config.add_route('api_other', '/v1/*api')
    config.scan()
    return config.make_wsgi_app()
