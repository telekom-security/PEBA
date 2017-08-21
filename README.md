# PEBA - Python EWS Backend API

Small backend application to offer an API alternative for current EWS backend, e.g. for the T-Pot Community backend. 

**Currently implemented endpoints:** 

 - [POST] */alert/retrieveIPs* ==> returning the unique IP addresses of the last attacks in timeframe *X* minutes. Requires authentication. 
 - [POST] */alert/retrieveAlertsCyber* ==> returning the last 1000 attacks. Requires authentication. 
 - [GET] */alert/retrieveAlertsCount* ==> returns the number of attacks within timespan in minutes or since the beginning of the current day e.g. */retrieveAlertsCount?time=10* or */retrieveAlertsCount?time=day*. Can further be parametrized using *out=json*. Defaults to xml.  
 - [GET] */alert/heartbeat* ==> Returns backend status : "*me*" if *everything* is ok, *m* if only mongoDB connection is ok, *e* if only elasticsearch connection is ok. If mongodb and elasticsearch connection fail, *flatline* is returned.
 - [GET] */alert/retrieveAlertsJson* ==> Returns last 5 Alerts in json for usage in sicherheitstacho
 - [GET] */alert/datasetAlertsPerMonth* ==> Returns attacks / day for */datasetAlertsPerMonth?days=x* in the last x days OR for the last month, defaults to last month, if no GET parameter "days" is given
 - [GET] */alert/datasetAlertTypesPerMonth* ==> Returns attacks / day, grouped by honeypot type, for */datasetAlertTypesPerMonth?days=x* in the last x days OR for the last month, defaults to last month, if no GET parameter "days" is given
 - [GET] */alert/retrieveAlertStats* ==> Returns combines statistics in one call: AlertsLastMinute, AlertsLastHour,  AlertsLast24Hours


**Install requirements:**

	easy_install hashlib
    pip install -r requirements.txt 


**Run Application:**

   	./start.sh


The webapplication runs on port 8000. It needs a [reverse proxy](http://flask.pocoo.org/docs/0.12/deploying/wsgi-standalone/#proxy-setups)  for SSL termination. 
Currently logs errors to `./error.log` - no access log.

The application can be tested using `./misc/test.sh` which will send the appropriate request to retrieve data. 


You need corresponding WSUser username & token to access the API. Replace them in `./misc/request.xml`
