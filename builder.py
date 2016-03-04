import sys
import signal
import os
import ConfigParser
import time
from io import BytesIO
import logging
import logging.config
import requests

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

from logentries import LogentriesHandler

requests.packages.urllib3.disable_warnings()

class BioshadockDaemon(Daemon):

  db_mongo = None
  db_redis = None
  cli = None

  def test(self, build, container_id):
      pass

  def run(self):
      config_file = "development.ini"
      if "BIOSHADOCK_CONFIG" in os.environ:
          config_file = os.environ["BIOSHADOCK_CONFIG"]
      config = ConfigParser.ConfigParser()
      config.readfp(open(config_file))
      logging.config.fileConfig(config_file)
      log = logging.getLogger(__name__)
      if config.get('app:main','logentries'):
          log.addHandler(LogentriesHandler(config.get('app:main','logentries')))
      log.warn("Starting a builder")
      do_squash = False
      if config.has_option('app:main', 'squash') and config.get('app:main', 'squash') == '1':
          do_squash = True

      while True:
          log.debug("New build run")
          if BioshadockDaemon.db_mongo is None:
              mongo = MongoClient(config.get('app:main','mongo_url'))
              BioshadockDaemon.db_mongo = mongo['mydockerhub']
          if BioshadockDaemon.db_redis is None:
              BioshadockDaemon.db_redis = redis.StrictRedis(host=config.get('app:main','redis_host'), port=int(config.get('app:main','redis_port')), db=0)
          if BioshadockDaemon.cli is None:
              if config.get('app:main', 'docker_connect'):
                  BioshadockDaemon.cli = Client(base_url=config.get('app:main',
                                                'docker_connect'),
                                                timeout=1800)
              else:
                  BioshadockDaemon.cli = Client(timeout=1800)
              BioshadockDaemon.cli.login(username=config.get('app:main','push_auth_user'), password=config.get('app:main','push_auth_password'),
                                         email=config.get('app:main','push_auth_email'),registry=config.get('app:main','service'))

          build = BioshadockDaemon.db_redis.lpop('bioshadock:builds')
          dockerfile = None
          if build is not None:
              build = loads(build)
              BioshadockDaemon.db_mongo['builds'].update({'_id': ObjectId(build['build'])},{'$set': {'progress': 'building'}})
              dt = datetime.datetime.now()
              timestamp = time.mktime(dt.timetuple())
              #log.debug(str(build))
              dockerfile = build['dockerfile']
              gitrepo = build['git']
              do_git = False
              git_repo_dir = None
              # CWL
              is_cwl = False
              cwl_is_url = False
              cwl = None
              if 'cwl_path' in build and build['cwl_path'] and build['cwl_path'] != 'none':
                  is_cwl = True
                  build['cwl_path'] = build['cwl_path'].encode('utf-8')
                  if build['cwl_path'].startswith('http'):
                      cwl_is_url = True
                      try:
                          r = requests.get(build['cwl_path'])
                          cwl = r.text.encode('utf-8')
                      except Exception as e:
                          log.error('Could not get CWL: '+str(build['cwl_path'])+" "+str(e))
              if gitrepo is not None and gitrepo and gitrepo != 'none':
                  # TODO clone repo in a dir, chdir to repo and optionally write
                  # dockerfile
                  git_repo_dir = tempfile.mkdtemp(suffix='.git')
                  git_info = gitrepo.split('#')
                  gitrepo = git_info[0]
                  selectedbranch = 'master'
                  subdir = None
                  if len(git_info) > 1:
                      branch_path = git_info[1].split(':')
                      if branch_path[0]:
                          selectedbranch = branch_path[0]
                      if len(branch_path) > 1 and branch_path[1]:
                          subdir = branch_path[1]
                  log.debug("Temporary directory: " + str(gitrepo))
                  log.info("Using branch " + selectedbranch)
                  log.info("Directory: " + str(subdir))
                  try:
                      Repo.clone_from(gitrepo, git_repo_dir, branch=selectedbranch)
                      if is_cwl and not cwl_is_url:
                          if build['cwl_path'].startswith('/'):
                              build['cwl_path'] = build['cwl_path'][1:]
                          cwl_file = os.path.join(git_repo_dir, build['cwl_path'])
                          if not os.path.exists(cwl_file):
                              log.error('Could not get CWL: '+str(build['cwl_path']))
                          else:
                              with open (cwl_file, "r") as cwlFile:
                                  cwl = cwlFile.read().encode('utf-8')
                      if subdir is not None:
                          git_repo_dir = os.path.join(git_repo_dir, subdir)
                      log.debug(str(git_repo_dir))
                      os.chdir(git_repo_dir)
                  except Exception as e:
                      logging.error(str(e))
                      BioshadockDaemon.db_mongo['builds'].update({'_id':
                      ObjectId(build['build'])},
                          {'$set': {'progress': 'failed',
                                    'response': [str(e)]
                                   }
                          })
                      continue
                  #if dockerfile:
                  if not os.path.exists("Dockerfile"):
                      log.debug("Overwrite Dockerfile")
                      f = open('Dockerfile', 'w')
                      f.write(dockerfile.encode('utf-8'))
                      f.close()
                  else:
                      log.debug("Use git Dockerfile")
                      with open ("Dockerfile", "r") as gitDockerfile:
                          dockerfile=gitDockerfile.read().encode('utf-8')

              f = BytesIO(dockerfile.encode('utf-8'))

              build_tag = ''
              info_tag = 'latest'
              if 'tag' in build and build['tag']:
                  build_tag = ':'+build['tag']
                  info_tag = build['tag']
              log.warn('Build: '+str(build['id']))

              response = None
              container_inspect = None
              try:
                  orig_build_tag = build_tag
                  if do_squash:
                      build_tag = ":squash"
                  response = [line for line in BioshadockDaemon.cli.build(
                      fileobj=f, rm=True, tag=config.get('app:main', 'service')+"/"+build['id']+build_tag, nocache=True)]
                  container_inspect = BioshadockDaemon.cli.inspect_image(config.get('app:main', 'service')+"/"+build['id']+build_tag)
              except Exception as e:
                  log.error('Build error: '+str(e))

              build['response'] = []
              for res in response:
                  try:
                      json_res = json.loads(res)
                      build['response'].append(json_res['stream'])
                  except Exception as e:
                      log.debug('Failed to decode json from stream output')
                      build['response'].append(res)

              if build['response']:
                  log.debug(str(response))
                  last = build['response'][len(build['response'])-1]
                  matches = re.search('Successfully built\s+(\w+)', last)
                  if matches is None:
                      build['status'] = False
                      log.info('Build error: '+str(build['id']))
                  else:
                      log.info('Successful build: '+str(build['id']))
                      build['status'] = True
                      build['image_id'] = matches.group(1)
                      #p= subprocess.Popen(["docker",
                      #                     "push",
                      #                     config.get('app:main', 'service')+"/"+build['id']])
                      #docker save 49b5a7a88d5 | sudo docker-squash -t jwilder/whoami:squash | docker load
                      if do_squash:
                          log.debug("Squash image "+config.get('app:main', 'service')+"/"+build['id']+build_tag)
                          log.debug("Save image")
                          p= subprocess.Popen(["docker",
                                         "save",
                                         "-o", "image.tar",
                                         config.get('app:main', 'service')+"/"+build['id']+build_tag,
                                         ])
                          p.wait()
                          log.debug("Squash image")
                          p= subprocess.Popen([ config.get('app:main', 'docker-squash'),
                                         "-i", "image.tar",
                                         "-o", "squashed.tar",
                                         "-t", config.get('app:main', 'service')+"/"+build['id']+orig_build_tag,
                                         ])
                          p.wait()
                          log.debug("Reload image")
                          p= subprocess.Popen([
                                         "docker", "load", "-i", "squashed.tar"
                                         ])
                          p.wait()
                      log.debug("Push image "+config.get('app:main', 'service')+"/"+build['id']+orig_build_tag)
                      try:
                          response = [line for line in BioshadockDaemon.cli.push(config.get('app:main', 'service')+"/"+build['id']+orig_build_tag, stream=True)]
                          log.debug(str(response))
                      except Exception as e:
                          log.error("Failed to push image: " + build['id']+ " "+str(e))
                          build['status'] = False
                          build['response'].append("Failed to push to registry")
                      try:
                          log.debug("Remove images for " + config.get('app:main', 'service')+"/"+build['id'])
                          BioshadockDaemon.cli.remove_image(config.get('app:main', 'service')+"/"+build['id']+orig_build_tag)
                          if do_squash:
                              log.debug("Remove squash image")
                              BioshadockDaemon.cli.remove_image(config.get('app:main', 'service')+"/"+build['id']+":squash")
                      except Exception as e:
                          log.error("Failed to remove image " + build['id']+ " "+str(e))

              else:
                  build['status'] = False
              if is_cwl and cwl is None:
                  build['response'].append("Failed to get CWL")
              build['timestamp'] = timestamp
              build['progress'] = 'over'
              entrypoint = None
              labels = []
              description = None
              size = None

              if not build['status']:
                  build['progress'] = 'failed'


              build['tag'] = info_tag

              if container_inspect is not None:
                  entrypoint = container_inspect['Config']['Entrypoint']
                  size = container_inspect['VirtualSize']
                  log.debug(str(container_inspect['Config']['Labels']))
                  for label in list(container_inspect['Config']['Labels'].keys()):
                      label_elts = container_inspect['Config']['Labels'][label]
                      if label.endswith('Description'):
                          description = label_elts
                      if label_elts.startswith('{') or label_elts.startswith('['):
                          try:
                              label_elts = json.loads(label_elts)
                          except Exception as e:
                              log.info("Failed to decode JSON for "+str(build['id'])+": "+str(label))
                      labels.append({label.replace('.', '_'): label_elts})

              meta_info = {'meta.Dockerfile': dockerfile,
                       'meta.cwl': cwl,
                       'meta.Entrypoint': entrypoint,
                       'meta.Dockerlabels': labels,
              }
              log.debug("Update repository "+build['id']+": "+str(meta_info))
              if description is not None:
                  meta_info['meta.docker_description'] = description
              if size is not None:
                  meta_info['meta.docker_tags.'+info_tag] = { 'size': int(size), 'last_updated': timestamp };
              if build['status']:
                  meta_info['meta.last_updated'] = timestamp

              BioshadockDaemon.db_mongo['builds'].update({'_id': ObjectId(build['build'])},build)
              BioshadockDaemon.db_mongo['repository'].update({'id': build['id']},
                                                       {'$set': meta_info})
              if do_git:
                  cur_dir = os.path.dirname(os.path.realpath(__file__))
                  os.chdir(cur_dir)
                  log.debug("Cleaning directory "+cur_dir+" => "+git_repo_dir)
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
