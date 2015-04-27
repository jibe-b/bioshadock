import sys
import signal
import os
import time
from io import BytesIO

import json
import datetime
from pymongo import MongoClient
from bson import json_util
from bson.objectid import ObjectId
import redis
import re
import subprocess
from daemon import Daemon

from docker import Client

class BioshadockDaemon(Daemon):

  db_mongo = None
  db_redis = None
  cli = None

  def run(self):
      while True:
          print "new run"
          if BioshadockDaemon.db_mongo is None:
              mongo = MongoClient('mongodb://localhost:27017/')
              BioshadockDaemon.db_mongo = mongo['mydockerhub']
          if BioshadockDaemon.db_redis is None:
              BioshadockDaemon.db_redis = redis.StrictRedis(host='localhost', port=6379, db=0)
          if BioshadockDaemon.cli is None:
              BioshadockDaemon.cli = Client(base_url='tcp://127.0.0.1:2375')
          build = BioshadockDaemon.db_redis.lpop('bioshadock:builds')
          if build is not None:
              build = json.loads(build)
              print str(build)
              dockerfile = build['dockerfile']
              f = BytesIO(dockerfile.encode('utf-8'))
              BioshadockDaemon.cli = Client(base_url='tcp://127.0.0.1:2375')
              response = [line for line in BioshadockDaemon.cli.build(
                  fileobj=f, rm=True, tag="cloud-30.genouest.org/"+build['id'])]
              build['response'] = response
              if build['response']:
                  last = build['response'][len(build['response'])-1]
                  matches = re.search('Successfully built\s+(\w+)', last)
                  if matches is None:
                      build['status'] = False
                  else:
                      build['status'] = True
                      build['image_id'] = matches.group(1)
                      p = subprocess.Popen(["docker","-H","127.0.0.1:2375","push","cloud-30.genouest.org/"+build['id']])
                      #response = [line for line in BioshadockDaemon.cli.push("cloud-30.genouest.org/"+build['id'], stream=True)]
                      #print str(response)

              else:
                  build['status'] = False
              BioshadockDaemon.db_mongo['repository'].update({'id': build['id']},{'$push': {'builds': build}})
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
