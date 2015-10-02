#!/bin/bash

if [ "$1" eq "web"]; then
    pserve development.ini
else
    python builder.py run
fi
