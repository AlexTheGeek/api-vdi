#!/bin/bash

if [[ ! -d "/var/log/VDI/API" ]]; then
    mkdir -p /var/log/VDI/API
    touch /var/log/VDI/API/access.log
    touch /var/log/VDI/API/error.log
    touch /var/log/VDI/API/api-flask.log
fi

python3 main.py
#gunicorn --access-logfile /var/log/VDI/API/access.log --error-logfile /var/log/VDI/API/error.log --workers 3 --bind 0.0.0.0:5001 main:app