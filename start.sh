#!/bin/bash

. /opt/bioshadock/benv/bin/activate

service apache2 start

if [ "$1" eq "web"]; then
    pserve development.ini
else
    python builder.py run
fi
