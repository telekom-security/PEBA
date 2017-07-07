#/bin/bash
# may be tweaked accordingly to
# http://docs.gunicorn.org/en/stable/settings.html

gunicorn webservice:app \
	-w 4 \
	-b 127.0.0.1 \
	--error-logfile error.log \
	--log-level error \
	--pid gunicorn.pid \
	# --user backendapi \
	# --group backendapi \
	# --daemon


# TODO: Deploy using 
# http://docs.gunicorn.org/en/stable/deploy.html

