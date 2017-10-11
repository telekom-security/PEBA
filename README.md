# PEBA - Python EWS Backend API

PEBA is a lightweight python3 backend application that offers an API alternative for the current DTAG EWS backend.

The API consists of two functional parts: A "PUT-Service" to store data and a "GET-Service" to retrieve data.

The PUT-API receives honeypot event data from [ewsposter](https://github.com/armedpot/ewsposter), e.g. from one or more [T-Pot](https://github.com/dtag-dev-sec/tpotce) installations, processes it and stores it in Elasticsearch.

`Attacker <--> T-Pot [honeypot <-- ewsposter] --> PEBA [Elasticsearch, memcache]`

The data stored can then be queried via distinct APIs, the GET-APIs. The results are cached for performance using memcached.

`Consumer, e.g. Sicherheitstacho.eu --> PEBA [Elasticsearch, memcache]`

It is crucial to understand that in PEBA honeypot data is devided in (1) *public community data* (everyone can contribute using T-Pot, submit and query data) and (2) data from *private domain honeypots* (e.g. those from DTAG) which can only be submitted and queried using distinct credentials. 

**Implemented API endpoints:** 

*Public/Private PUT endpoint* using authentication to deliver honeypot events using ewsposter. 

 - [POST] */ews-0.1/alert/postSimpleMessage* ==> takes the ews xml posted by ewsposter, processes and stores honeypot alerts in elasticsearch, flagged with domain

The authentication can be done using either T-Pot community credentials (1) or distinct EWS user for the private domain (2). The username & token is stored in ewsposter's ews.cfg residing on T-Pot. Depending on the credentials, the data is flagged as community data (1) or private domain data (2).

*Private GET endpoints* using authentication:

 - [POST] */alert/retrieveIPs* ==> returning the unique IP addresses of the last attacks in timeframe *X* minutes.
 - [POST] */alert/retrieveAlertsCyber* ==> returning the last 1000 attacks, including IPs. 

The above private endpoints cannot be queried using the community credentials (1), only by users of the private domain (2).

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
 

 
**Data domain:**

By default, querying the above endpoints, data from the **T-Pot community honeypots** is returned. To retrieve data from the **private domain honeypots**, add a GET parameter *ci=0*. Example:  */alert/retrieveAlertsJson?**ci=0*** to retrieve the private json data feed. This works both on the public and private endpoints.


**Installation:** (on Debian/Ubuntu)


    sudo apt-get install python3 python3-dev python3-pip python3-pylibmc
    git clone git@github.com:dtag-dev-sec/PEBA.git
	cd PEBA
    sudo mkdir -p /etc/ews/
	sudo cp etc/ews/peba.cfg /etc/ews/peba.cfg
	pip3 install -r requirements.txt
    cd var/lib/GeoIP/
	./download.sh
    
*Reminder:* Elasticsearch and memcached must be available. They must be configured in */etc/ews/peba.cfg*. 

*Note:*  When installing on MacOS, you need the following: 
` brew install libmemcached` and `pip3 install pylibmc`

**Run Application:**

You can run the application (for testing) via:

   	./start.sh
   	
The webapplication runs on port 9922. Running as shown above, PEBA logs errors to `./error.log`. 

**Deploy Application:**

In production environments it needs a [reverse proxy](http://flask.pocoo.org/docs/0.12/deploying/wsgi-standalone/#proxy-setups) for SSL termination.
The application can be deployed via ansible on a debian (tested: Stretch) / ubuntu (tested 16.04) system and started using a systemd script. As mentioned before, PEBA further relies on an Elasticsearch and memcache installation which needs to be configured separately. Adjust ./ansible/hosts with the correct paramters (hostname and following operational values). Then deploy via:

    ./ansible/deploy.sh <prod|test>


**Adding users:**

In order to add users to the authentication pool - for the usage of the private domain, the script `./misc/add-user.py` can be used. 


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
