import sys
import signal
import os
import ConfigParser
import time
from io import BytesIO
import logging
import logging.config

import json
import datetime
import time
from pymongo import MongoClient
from bson import json_util
from bson.json_util import loads
from bson.objectid import ObjectId
import redis
import re
import subprocess
import tempfile
import shutil
from daemon import Daemon

from docker import Client

from git.repo.base import Repo

class BioshadockDaemon(Daemon):

  db_mongo = None
  db_redis = None
  cli = None

  def run(self):
      config_file = "development.ini"
      if "BIOSHADOCK_CONFIG" in os.environ:
          config_file = os.environ["BIOSHADOCK_CONFIG"]
      config = ConfigParser.ConfigParser()
      config.readfp(open(config_file))
      logging.config.fileConfig(config_file)
      while True:
          logging.info("New build run")
          if BioshadockDaemon.db_mongo is None:
              mongo = MongoClient(config.get('app:main','mongo_url'))
              BioshadockDaemon.db_mongo = mongo['mydockerhub']
          if BioshadockDaemon.db_redis is None:
              BioshadockDaemon.db_redis = redis.StrictRedis(host=config.get('app:main','redis_host'), port=int(config.get('app:main','redis_port')), db=0)
          if BioshadockDaemon.cli is None:
              if config.get('app:main', 'docker_connect'):
                  BioshadockDaemon.cli = Client(base_url=config.get('app:main',
                                                'docker_connect'))
              else:
                  BioshadockDaemon.cli = Client()
              BioshadockDaemon.cli.login(username=config.get('app:main','push_auth_user'), password=config.get('app:main','push_auth_password'),
                                         email=config.get('app:main','push_auth_email'),registry=config.get('app:main','service'))

          build = BioshadockDaemon.db_redis.lpop('bioshadock:builds')
          dockerfile = None
          if build is not None:
              dt = datetime.datetime.now()
              timestamp = time.mktime(dt.timetuple()) 
              build = loads(build)
              logging.debug(str(build))
              dockerfile = build['dockerfile']
              gitrepo = build['git']
              do_git = False
              git_repo_dir = None
              if gitrepo is not None and gitrepo and gitrepo != 'none':
                  # TODO clone repo in a dir, chdir to repo and optionally write
                  # dockerfile
                  git_repo_dir = tempfile.mkdtemp(suffix='.git')
                  Repo.clone_from(gitrepo, git_repo_dir)
                  logging.debug(str(git_repo_dir))
                  os.chdir(git_repo_dir)
                  if dockerfile:
                      logging.debug("Overwrite Dockerfile")
                      f = open('Dockerfile', 'w')
                      f.write(dockerfile.encode('utf-8'))
                      f.close()
                  else:
                      logging.debug("Use git Dockerfile")
                      with open ("Dockerfile", "r") as gitDockerfile:
                          dockerfile=gitDockerfile.read().encode('utf-8')

              f = BytesIO(dockerfile.encode('utf-8'))

              build_tag = ''
              if 'tag' in build and build['tag']:
                  build_tag = ':'+build['tag']
              logging.info('Build: '+str(build['id']))
              response = [line for line in BioshadockDaemon.cli.build(
                  fileobj=f, rm=True, tag=config.get('app:main', 'service')+"/"+build['id']+build_tag)]
              build['response'] = response
              if build['response']:
                  last = build['response'][len(build['response'])-1]
                  matches = re.search('Successfully built\s+(\w+)', last)
                  if matches is None:
                      build['status'] = False
                  else:
                      build['status'] = True
                      build['image_id'] = matches.group(1)
                      p= subprocess.Popen(["docker",
                                        "push",
                                        config.get('app:main', 'service')+"/"+build['id']])

              else:
                  build['status'] = False
              build['timestamp'] = timestamp
              BioshadockDaemon.db_mongo['repository'].update({'id': build['id']},
                                                       {'$push': {'builds': build},
                                                       '$set':{'meta.Dockerfile': dockerfile}})
              if do_git:
                  cur_dir = os.path.dirname(os.path.realpath(__file__))
                  os.chdir(cur_dir)
                  shutil.rmtree(git_repo_dir)
          time.sleep(2)


if __name__ == "__main__":
        daemon = BioshadockDaemon('/tmp/godsched.pid')

        if len(sys.argv) == 2:
                if 'start' == sys.argv[1]:
                        daemon.start()
                elif 'stop' == sys.argv[1]:
                        daemon.stop()
                elif 'restart' == sys.argv[1]:
                        daemon.restart()
                elif 'run' == sys.argv[1]:
                        daemon.run()
                else:
                        print "Unknown command"
                        sys.exit(2)
                sys.exit(0)
        else:
                print "usage: %s start|stop|restart|run" % sys.argv[0]
                sys.exit(2)
