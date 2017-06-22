#/bin/bash

gunicorn webservice:app -w 4 -b 127.0.0.1

