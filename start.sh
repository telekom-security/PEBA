#!/usr/bin/env bash

[ ! -f /etc/peba/peba.cfg ] && echo "### PEBA: Config file /etc/peba/peba.cfg missing. Copy peba.cfg to /etc/peba/. Abort." && exit 1

BIND=$(cat /etc/peba/peba.cfg|grep BINDHOST|cut -d "\"" -f2)


pip3 install -r requirements.txt

# may be tweaked accordingly to
# http://docs.gunicorn.org/en/stable/settings.html

python3 $(which gunicorn) peba:app \
	-w 4 \
	-b $BIND
	--error-logfile error.log \
	--log-level error \
	--pid gunicorn.pid \
	# --user backendapi \
	# --group backendapi \
	# --daemon
