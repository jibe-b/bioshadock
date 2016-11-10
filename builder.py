import sys
import signal
import os
import time
from io import BytesIO
import logging
import logging.config
import requests
import base64
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
import yaml
from daemon import Daemon

from docker import Client

from git.repo.base import Repo

from logentries import LogentriesHandler

from clair.clair import Clair

import copy
from elasticsearch import Elasticsearch


requests.packages.urllib3.disable_warnings()


class BioshadockDaemon(Daemon):

    es = None
    db_mongo = None
    db_redis = None
    cli = None
    run_once = False

    def test(self, build, container_id):
        pass

    def analyse_with_clair(self, image_id):
        self.log.debug('Analyse '+image_id+' with Clair')
        cfg = {
            'clair.host': self.config['clair']['host'],
            'docker.connect': self.config['services']['docker']['connect']
        }
        clair_analyse = Clair(cfg)

        layers = clair_analyse.analyse(image_id)
        layer_ids = []
        for layer in layers:
            layer_ids.append(layer['id'])
        return layer_ids


    def stats(self):
        config_file = "config.yaml"
        if "BIOSHADOCK_CONFIG" in os.environ:
            config_file = os.environ["BIOSHADOCK_CONFIG"]

        self.config= None
        with open(config_file, 'r') as ymlfile:
            self.config = yaml.load(ymlfile)

        BioshadockDaemon.db_redis = redis.StrictRedis(
                                host=self.config['services']['redis']['host'],
                                port=self.config['services']['redis']['port'],
                                db=self.config['services']['redis']['db']
                                )

        queues = BioshadockDaemon.db_redis.hkeys('bioshadock:user:builds')
        print("Build usage:")
        for queue in queues:
            print("\t%s: %s, in queue: %d" % (queue,
                        BioshadockDaemon.db_redis.hget('bioshadock:user:builds', queue),
                        BioshadockDaemon.db_redis.llen('bioshadock:builds:' + queue)))
        sys.exit(0)


    def run(self):
        config_file = "config.yaml"
        if "BIOSHADOCK_CONFIG" in os.environ:
            config_file = os.environ["BIOSHADOCK_CONFIG"]

        self.config= None
        with open(config_file, 'r') as ymlfile:
            self.config = yaml.load(ymlfile)

        if self.config['log_config'] is not None:
            for handler in list(self.config['log_config']['handlers'].keys()):
                self.config['log_config']['handlers'][handler] = dict(self.config['log_config']['handlers'][handler])
            logging.config.dictConfig(self.config['log_config'])
        log = logging.getLogger('builder')
        self.log = log

        '''
        config = ConfigParser.ConfigParser()
        config.readfp(open(config_file))
        self.config = config
        logging.config.fileConfig(config_file)
        log = logging.getLogger(__name__)
        self.log = log


        if config.has_option('app:main', 'logentries'):
            log.addHandler(
                LogentriesHandler(config.get('app:main', 'logentries')))
        '''

        log.warn("Starting a builder")
        do_squash = False
        if self.config['general']['squash']['use'] == 1:
            do_squash = True

        queue_counter = 0

        while True:
            if os.path.exists('/tmp/bioshadocker-builder.stop'):
                log.warn('Request to exit: /tmp/bioshadocker-builder.stop')
                break
            log.debug("New build run")
            if BioshadockDaemon.db_mongo is None:
                mongo = MongoClient(self.config['services']['mongo']['url'])
                BioshadockDaemon.db_mongo = mongo[self.config['services']['mongo']['db']]
            if BioshadockDaemon.es is None:
                BioshadockDaemon.es = Elasticsearch(self.config['services']['elastic']['host'].split(','))
            if BioshadockDaemon.db_redis is None:
                BioshadockDaemon.db_redis = redis.StrictRedis(
                                host=self.config['services']['redis']['host'],
                                port=self.config['services']['redis']['port'],
                                db=self.config['services']['redis']['db']
                                )
            if BioshadockDaemon.cli is None:
                timeout=1800
                if self.config['services']['docker']['timeout']:
                    timeout = self.config['services']['docker']['timeout']
                if self.config['services']['docker']['connect']:
                    BioshadockDaemon.cli = Client(
                        base_url=self.config['services']['docker']['connect'],
                        timeout=timeout
                        )
                else:
                    BioshadockDaemon.cli = Client(timeout=timeout)
                if self.config['registry']['push'] == 0:
                    log.debug('Local docker, not using registry')
                else:
                    BioshadockDaemon.cli.login(
                        username=self.config['registry']['auth']['user'],
                        password=self.config['registry']['auth']['password'],
                        email=self.config['registry']['auth']['email'],
                        registry=self.config['registry']['service'])

            queues = BioshadockDaemon.db_redis.hkeys('bioshadock:user:builds')

            user_id = None

            if queue_counter >= len(queues):
                log.debug("Queue: go back to beginning")
                queue_counter = 0


            build = None

            while build is None and queue_counter < len(queues):
                user_id = queues[queue_counter]
                log.debug("Queue:Check:%s" % (user_id))
                build = BioshadockDaemon.db_redis.lpop('bioshadock:builds:' + user_id)
                queue_counter += 1

            dockerfile = None
            if build is not None:
                log.info("Build queue: %s" % (user_id))
                build = loads(build)
                log.info('Build request: ' + str(build['id']))
                BioshadockDaemon.db_mongo['builds'].update(
                    {'_id': ObjectId(build['build'])}, {'$set': {'progress': 'building'}})
                dt = datetime.datetime.now()
                timestamp = time.mktime(dt.timetuple())
                # log.debug(str(build))
                dockerfile = build['dockerfile']
                gitrepo = build['git']
                do_git = False
                git_repo_dir = None
                # CWL
                is_cwl = False
                cwl_is_url = False
                cwl = None
                entrypoint = None
                description = None
                tags = []
                size = None
                labels = []
                layer_ids = []
                clair_check = False

                if 'cwl_path' in build and build['cwl_path'] and build['cwl_path'] != 'none':
                    is_cwl = True
                    build['cwl_path'] = build['cwl_path'].encode('utf-8')
                    if build['cwl_path'].startswith('http'):
                        cwl_is_url = True
                        try:
                            r = requests.get(build['cwl_path'])
                            cwl = r.text.encode('utf-8')
                        except Exception as e:
                            log.error(
                                'Could not get CWL: ' + str(build['cwl_path']) + " " + str(e))

                git_repo_dir = None
                if gitrepo is not None and gitrepo and gitrepo != 'none':
                    # dockerfile
                    git_repo_dir = tempfile.mkdtemp(suffix='.git')
                    do_git = True
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
                        Repo.clone_from(
                            gitrepo, git_repo_dir, branch=selectedbranch)
                        if is_cwl and not cwl_is_url:
                            if build['cwl_path'].startswith('/'):
                                build['cwl_path'] = build['cwl_path'][1:]
                            cwl_file = os.path.join(
                                git_repo_dir, build['cwl_path'])
                            if not os.path.exists(cwl_file):
                                log.error(
                                    'Could not get CWL: ' + str(build['cwl_path']))
                            else:
                                with open(cwl_file, "r") as cwlFile:
                                    cwl = cwlFile.read().encode('utf-8')
                        if subdir is not None:
                            git_repo_dir = os.path.join(git_repo_dir, subdir)
                        log.debug(str(git_repo_dir))
                        os.chdir(git_repo_dir)
                    except Exception as e:
                        logging.error('Git error: ' + str(e))
                        BioshadockDaemon.db_mongo['builds'].update({'_id':
                                                                    ObjectId(
                                                                        build[
                                                                            'build'])},
                                                                   {'$set': {'progress': 'failed',
                                                                             'response': [str(e)]
                                                                             }
                                                                    })
                        continue
                    # if dockerfile:
                    if not os.path.exists("Dockerfile"):
                        log.debug("Overwrite Dockerfile")
                        f = open('Dockerfile', 'w')
                        f.write(dockerfile.encode('utf-8'))
                        f.close()
                    else:
                        try:
                            log.debug("Use git Dockerfile")
                            with open("Dockerfile", "r") as gitDockerfile:
                                dockerfile = gitDockerfile.read().encode('utf-8')
                        except Exception as e:
                            log.error('Failed to decode Docker file: '+str(e))
                            build['progress'] = 'failed'
                            build['response'] = ['Failed to decode dockerfile: '+str(e)]
                            BioshadockDaemon.db_mongo['builds'].update(
                                {'_id': ObjectId(build['build'])}, build)
                            continue


                f = BytesIO(dockerfile.encode('utf-8'))

                build_tag = ''
                info_tag = 'latest'
                if 'tag' in build and build['tag']:
                    build_tag = ':' + build['tag']
                    info_tag = build['tag']
                log.warn('Build: ' + str(build['id']) + ':' + str(info_tag))

                response = []
                container_inspect = None
                build_ok = False
                try:
                    orig_build_tag = build_tag
                    if do_squash:
                        build_tag = ":squash"
                    if do_git:
                         response = [line for line in BioshadockDaemon.cli.build(
                            path=git_repo_dir, rm=True, tag=self.config['registry']['service'] + "/" + build['id'] + build_tag, nocache=True, timeout=self.config['services']['docker']['timeout'])]                   
                    else:
                        response = [line for line in BioshadockDaemon.cli.build(
                            fileobj=f, rm=True, tag=self.config['registry']['service'] + "/" + build['id'] + build_tag, nocache=True, timeout=self.config['services']['docker']['timeout'])]
                except Exception as e:
                    log.error('Build error: ' + str(e))
                    response += [str(e)]
                try:
                    container_inspect = BioshadockDaemon.cli.inspect_image(
                        self.config['registry']['service'] + "/" + build['id'] + build_tag)
                    build_ok = True
                except Exception as e:
                    log.error('Inspect error: ' + str(e))
                    response += [str(e)]

                build['response'] = []
                for res in response:
                    try:
                        json_res = json.loads(res)
                        build['response'].append(json_res['stream'])
                    except Exception as e:
                        log.debug('Failed to decode json from stream output')
                        build['response'].append(res)

                if build['response'] and build_ok:
                    log.debug(str(response))
                    last = build['response'][len(build['response']) - 1]
                    matches = re.search('Successfully built\s+(\w+)', last)
                    if matches is None:
                        build['status'] = False
                        log.info('Build error: ' + str(build['id']))
                    else:
                        log.info('Successful build: ' + str(build['id']))
                        build['status'] = True
                        build['image_id'] = matches.group(1)
                        tests = []
                        if container_inspect is not None:
                            entrypoint = container_inspect['Config']['Entrypoint']
                            size = container_inspect['VirtualSize']
                            log.debug(
                                str(container_inspect['Config']['Labels']))
                            for label in list(container_inspect['Config']['Labels'].keys()):
                                label_elts = container_inspect[
                                    'Config']['Labels'][label]
                                if label.lower().endswith('description'):
                                    description = label_elts
                                if label.lower().endswith('tags'):
                                    tags = label_elts.split(',')
                                if label_elts.startswith('{') or label_elts.startswith('['):
                                    try:
                                        label_elts = json.loads(label_elts)
                                    except Exception as e:
                                        log.debug(
                                            "Failed to decode JSON for " + str(build['id']) + ": " + str(label))
                                labels.append(
                                    {label.replace('.', '_'): label_elts})
                                if label == 'bioshadock.tests':
                                    tests = json.loads(
                                        base64.decodestring(label_elts))
                        if not tests and git_repo_dir and os.path.exists(os.path.join(git_repo_dir, 'test.yaml')):
                            log.debug('Load test.yaml for ' + build['id'] + 'from git repo')
                            with open(os.path.join(git_repo_dir, 'test.yaml'), 'r') as ymlfile:
                                commands = yaml.load(ymlfile)
                                tests = commands['test']['commands']
                        if tests:
                            for test in tests:
                                test_container = None
                                try:
                                    build['response'].append(
                                        "Test: " + str(test) + "\n")
                                    log.debug("Execute test for " + self.config['registry']['service'] + "/" + build['id'] + build_tag + ": " + str(test))
                                    if '"' in test:
                                        build['response'].append("Test:Skipping:test contains double quotes:"+test)
                                        log.debug("Test:Skipping:test contains double quotes:"+test)
                                        continue
                                    command='sh -c "'+test+'"'
                                    if git_repo_dir is not None:
                                        host_config = BioshadockDaemon.cli.create_host_config(binds={
                                            git_repo_dir: {
                                                'bind': '/repo',
                                                'mode': 'rw',
                                            }
                                        })
                                        test_container = BioshadockDaemon.cli.create_container(
                                            image=self.config['registry']['service'] + "/" + build['id'] + build_tag, command=command, host_config=host_config, environment=["R=R"])
                                    else:
                                        test_container = BioshadockDaemon.cli.create_container(
                                            image=self.config['registry']['service'] + "/" + build['id'] + build_tag, command=command, environment=["R=R"])

                                    response = BioshadockDaemon.cli.start(
                                        container=test_container.get('Id'))
                                    time.sleep(2)
                                    test_container_inspect = BioshadockDaemon.cli.inspect_container(
                                        test_container.get('Id'))
                                    if test_container_inspect['State']['ExitCode'] != 0:
                                        build['status'] = False
                                        build['response'].append(
                                            "Test result: Failed\n")
                                    else:
                                        build['response'].append(
                                            "Test result: Success\n")

                                except Exception as e:
                                    log.error("failed to test container " + self.config['registry']['service'] + "/" + build['id'] + build_tag + ': '+str(e))
                                    build['status'] = False
                                    build['response'].append("Test result: Failed\n")
                                try:
                                    if test_container is not None:
                                        BioshadockDaemon.cli.remove_container(
                                            container=test_container.get('Id'))
                                except Exception as e:
                                    log.error('Failed to remove test container '+str(test_container.get('Id'))+': '+str(e))

                                if not build['status']:
                                    break
                        # p= subprocess.Popen(["docker",
                        #                     "push",
                        #                     config.get('app:main', 'service')+"/"+build['id']])
                        # docker save 49b5a7a88d5 | sudo docker-squash -t
                        # jwilder/whoami:squash | docker load
                        if do_squash and build['status']:
                            log.debug("Squash image " + self.config['registry']['service'] + "/" + build['id'] + build_tag)
                            log.debug("Save image")
                            (squash_image_handler, squash_image_file) = tempfile.mkstemp(suffix='.squash.tar')
                            (squashed_image_handler, squashed_image_file) = tempfile.mkstemp(suffix='.squashed.tar')

                            p = subprocess.Popen(["docker",
                                                  "save",
                                                  #"-o", "image.tar",
                                                  '-o', squash_image_file,
                                                  self.config['registry']['service'] + "/" + build[
                                                  'id'] + build_tag,
                                                  ])
                            p.wait()
                            log.debug("Squash image")
                            p = subprocess.Popen(
                                [self.config['general']['squash']['docker-squash'],
                                 #"-i", "image.tar",
                                 "-i", squash_image_file,
                                 #"-o", "squashed.tar",
                                 "-o", squashed_image_file,
                                 "-t", self.config['registry']['service'] + "/" + build['id'] + orig_build_tag,
                                 ])
                            p.wait()
                            log.debug("Reload image")
                            p = subprocess.Popen([
                                "docker", "load", "-i", squashed_image_file
                                 #"docker", "load", "-i", "squashed.tar"
                            ])
                            p.wait()
                            if os.path.exists(squash_image_file):
                                os.remove(squash_image_file)
                            if os.path.exists(squashed_image_file):
                                os.remove(squashed_image_file)

                        if build['status'] and self.config['clair']['use'] == 1:
                            log.debug('Analyse with Clair')
                            clair_check = True
                            layer_ids = self.analyse_with_clair(self.config['registry']['service'] + "/" + build['id'] + orig_build_tag)


                        if self.config['registry']['push'] == 0:
                            log.debug("Skip image push, keep local " + self.config['registry']['service'] + "/" + build['id'] + orig_build_tag)
                            try:
                                if do_squash:
                                    log.debug("Remove squash image")
                                    BioshadockDaemon.cli.remove_image(
                                        self.config['registry']['service'] + "/" + build['id'] + ":squash")
                            except Exception as e:
                                log.error(
                                    "Failed to remove image " + build['id'] + " " + str(e))
                        else:
                            if build['status']:
                                log.warn("Push image " + self.config['registry']['service'] + "/" + build['id'] + orig_build_tag)
                                try:
                                    response = [line for line in BioshadockDaemon.cli.push(
                                        self.config['registry']['service'] + "/" + build['id'] + orig_build_tag, stream=True)]
                                except Exception as e:
                                    log.error(
                                        "Failed to push image: " + build['id'] + " " + str(e))
                                    build['status'] = False
                                    build['response'].append(
                                        "Failed to push to registry")
                            try:
                                log.debug("Remove images for " + self.config['registry']['service'] + "/" + build['id'])
                                if do_squash:
                                    log.debug("Remove squash image")
                                    BioshadockDaemon.cli.remove_image(
                                        self.config['registry']['service'] + "/" + build['id'] + ":squash")
                                BioshadockDaemon.cli.remove_image(
                                    self.config['registry']['service'] + "/" + build['id'] + orig_build_tag)
                            except Exception as e:
                                log.error(
                                    "Failed to remove image " + build['id'] + " " + str(e))

                else:
                    build['status'] = False
                if is_cwl and cwl is None:
                    build['response'].append("Failed to get CWL")
                build['timestamp'] = timestamp
                build['progress'] = 'over'

                if not build['status']:
                    build['progress'] = 'failed'

                build['tag'] = info_tag

                meta_info = {'meta.Dockerfile': dockerfile,
                             'meta.cwl': cwl,
                             'meta.Entrypoint': entrypoint,
                             'meta.Dockerlabels': labels,
                             'meta.layers': layer_ids,
                             'meta.version.'+info_tag.replace('.','_')+'.layers': layer_ids,
                             'meta.clair': clair_check
                             }
                if tags:
                    meta_info['meta.tags'] = tags
                log.debug(
                    "Update repository " + build['id'] + ": " + str(meta_info))
                if description is not None:
                    meta_info['meta.docker_description'] = description
                if size is not None:
                    meta_info['meta.docker_tags.' + info_tag.replace('.','_')] = {
                        'size': int(size), 'last_updated': timestamp, 'tag': info_tag}
                if build['status']:
                    meta_info['meta.last_updated'] = timestamp
                    meta_info['meta.built'] = True

                BioshadockDaemon.db_mongo['builds'].update(
                    {'_id': ObjectId(build['build'])}, build)
                BioshadockDaemon.db_mongo[
                    'repository'].update({'id': build['id']},
                                         {'$set': meta_info})

                # Record specific tag info
                if build['status']:
                    BioshadockDaemon.db_mongo['versions'].update(
                            {'repo': build['id'], 'version': info_tag},
                            {
                                'repo': build['id'],
                                'version': info_tag,
                                'dockerfile': dockerfile,
                                'cwl': cwl
                            },
                            upsert=True
                            )

                log.debug('Update indexation')
                updated_container = BioshadockDaemon.db_mongo['repository'].find_one({'id': build['id']})
                es_repo = copy.deepcopy(updated_container)
                del es_repo['_id']
                del es_repo['builds']
                del es_repo['meta']
                es_repo['meta'] = {'description': updated_container['meta']['description'],
                                   'short_description': updated_container['meta']['short_description'],
                                   'tags': updated_container['meta']['tags']
                }
                BioshadockDaemon.es.index(index="bioshadock", doc_type='container', id=build['id'], body=es_repo)


                if do_git:
                    cur_dir = os.path.dirname(os.path.realpath(__file__))
                    os.chdir(cur_dir)
                    log.debug(
                        "Cleaning directory " + cur_dir + " => " + git_repo_dir)
                    shutil.rmtree(git_repo_dir)
            if self.run_once:
                break
            time.sleep(2)


if __name__ == "__main__":
    pid_file = "/tmp/bioshadockbuilder.pid"
    if "BIOSHADOCK_PID" in os.environ:
        pid_file = os.environ["BIOSHADOCK_PID"]
    daemon = BioshadockDaemon(pid_file)

    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        elif 'run' == sys.argv[1]:
            daemon.run()
        elif 'once' == sys.argv[1]:
            daemon.run_once = True
            daemon.run()
        elif 'stats' == sys.argv[1]:
            daemon.stats()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart|run|once|stats" % sys.argv[0]
        sys.exit(2)
