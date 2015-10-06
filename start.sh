#!/bin/bash

. /opt/bioshadock/benv/bin/activate

service apache2 start

if [ "$1" = "web" ]; then
    gunicorn -p bioshadock.pid --log-config=production.ini --paste production.ini
fi
if [ "$1" = "dev" ]; then
    pserve development.ini
fi
if [ "$1" = "builder" ]; then
    python builder.py run
fi
