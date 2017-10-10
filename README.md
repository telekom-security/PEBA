# PEBA - Python EWS Backend API

PEBA is a lightweight python3 backend application which offers an API alternative for current EWS backend. The API receives honeypot event data from [ewsposter](https://github.com/armedpot/ewsposter), e.g. from one or more [T-Pot](https://github.com/dtag-dev-sec/tpotce) installations, processes it and stores it in Elasticsearch. The data stored can be queried via the APIs below.

**Currently implemented API endpoints:** 

*Private GET endpoints* using authentication:

 - [POST] */alert/retrieveIPs* ==> returning the unique IP addresses of the last attacks in timeframe *X* minutes. Requires authentication. 
 - [POST] */alert/retrieveAlertsCyber* ==> returning the last 1000 attacks. Requires authentication.


*Public GET endpoints* for Sicherheitstacho:
 
 - [GET] */alert/retrieveAlertsCount* ==> returns the number of attacks within timespan in minutes or since the beginning of the current day e.g. */retrieveAlertsCount?time=10* or */retrieveAlertsCount?time=day*. Can further be parametrized using *out=json*. Defaults to xml.  
 - [GET] */alert/heartbeat* ==> Returns backend status : "*me*" if *everything* is ok, *m* if only mongoDB connection is ok, *e* if only elasticsearch connection is ok. If mongodb and elasticsearch connection fail, *flatline* is returned.
 - [GET] */alert/retrieveAlertsJson* ==> Returns last 5 Alerts in json for usage in sicherheitstacho
 - [GET] */alert/datasetAlertsPerMonth* ==> Returns attacks / day for */datasetAlertsPerMonth?days=x* in the last x days OR for the last month, defaults to last month, if no GET parameter "days" is given
 - [GET] */alert/datasetAlertTypesPerMonth* ==> Returns attacks / day, grouped by honeypot type, for */datasetAlertTypesPerMonth?days=x* in the last x days OR for the last month, defaults to last month, if no GET parameter "days" is given
 - [GET] */alert/retrieveAlertStats* ==> Returns combines statistics in one call: AlertsLastMinute, AlertsLastHour,  AlertsLast24Hours
 - [GET] */alert/topCountriesAttacks* ==> Returns information on the Top 10 attacker countries and top 10 attacked countries. use GET parameter "offset" and "topx" to determine the offset from this month (default: this month) and how many results shall be returned (default: top10)
 - [GET] */alert/retrieveLatLonAttacks* ==> Returns top X count on Lat and Lng. use GET parameter "offset" and "topx" to determine the offset from now in days (default: last 24h) and how many results shall be returned (default: top10). Use parameter "direction" to determine if source or destination location is given.
 - [GET] */alert/retrieveAlertsCountWithType* ==> returns the number of attacks within timespan in minutes or since the beginning of the current day, grouped by Type, e.g. */retrieveAlertsCountWithType?time=10* or */retrieveAlertsCountWithType?time=day*. Returns json.
 
*Public PUT endpoint* using authentication (either T-Pot Community or distinct EWS WSUser):
 - [POST] */ews-0.1/alert/postSimpleMessage* ==> takes the ews xml posted and puts honeypot alerts into elasticsearch
 
***Data domain:***

By default, queriying the above endpoints, data from the **community honeypots** is returned. To retrieve data from the **DTAG honeypots**, add a GET parameter *ci=0*. Example:  */alert/retrieveAlertsJson?****ci=0*** to retrieve the DTAG json data feed. This works both on the public and private endpoints.


**Install requirements:**

    apt-get install python3 python3-dev python3-pip 
    pip3 install -r requirements.txt


**Run Application:**

Run the application (for testing) via:

   	./start.sh
   	
The webapplication runs on port 9922. It needs a [reverse proxy](http://flask.pocoo.org/docs/0.12/deploying/wsgi-standalone/#proxy-setups)  for SSL termination.
Running as shown above, it logs errors to `./error.log`.

**Deploy Application:**

The application can be deployed via ansible on a debian (tested: Stretch) / ubuntu (tested 16.04) system and started using a systemd script. PEBA further relies on an elasticsearch and memcache installation which needs to be configured separately. Adjust ./ansible/hosts with the correct paramters (hostname and following operational values). Then deploy via:

    ./ansible/deploy.sh <prod|test>


** Adding users: **

In order to add users to the authentication pool, the script `./misc/add-user.py` can be used. 


**Functional Tests:**

The application consists of two part, a GET and a PUT Service. It can be tested using `./misc/test-getService.sh` respectively `./misc/test-putService.sh` which will send appropriate requests to retrieve or store data. Again, prod and test instance can be tested, further community data or private (dtag honeypots) data can be retrieved (only GET). Change the config section in script according to your environment.

    ./misc/test-getService.sh <prod|test> <private|community>
    ./misc/test-putService.sh <prod|test>

For some of the above requests, you need a username & password in order to access the API. Use the script `./misc/add-user.py` to add new users and replace the file username and token in `./misc/request.xml`. 


**Credits**

Code by André Vorbach (vorband) and Markus Schmall (schmalle).

Overall help, friendly extensions / comments / suggestions by Markus Schroer and Robin Verton.
Valuable discussions with Aydin Kocas, Markus Schroer, Marco Ochse, Robin Verton and Rainer Schmidt.

Used frameworks / tools:

Maxmind GeoIP (https://dev.maxmind.com/geoip/legacy/geolite/) Gunicorn Flask Elasticsearch
