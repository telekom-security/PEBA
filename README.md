# PEBA - Python EWS Backend API


## **Intro:**

PEBA is a lightweight python3 backend service to collect and process attack events captured by honyeypot daemons, in particular those running on our multi honeypot plattform [T-Pot](https://github.com/dtag-dev-sec/tpotce). PEBA can serve as a centralized data collection tool for distributed T-Pot installations.

PEBA is running in production @DTAG since October 2017 and serves as a replacement for our previous grails-based backend, which was developed by our friend Lutz Wischmann. We use PEBA to collect honeypot events from both our own private DTAG honeypot network as well as community data contribution from T-Pots running all over the world. 

The data is visualized on our new [sicherheitstacho.eu](http://community.sicherheitstacho.eu) website.


## **Overview:**

PEBA's API consists of two functional parts: 

A **PUT-Service** to process and store attack data and a **GET-Service** to retrieve data.

The PUT-API receives honeypot events from our honeypot attack data aggregation tool [ewsposter](https://github.com/armedpot/ewsposter), e.g. from one or more T-Pot installations, processes it and stores it in Elasticsearch.

`Attacker <--> T-Pot [honeypot[1..n] <-- ewsposter] --> PEBA PUT Service [Elasticsearch, memcache]`

The data stored can then be queried via distinct APIs, the GET-APIs. The results from Elasticsearch are cached for performance using memcached.

`Consumer, e.g. sicherheitstacho.eu --> PEBA GET-Service [Elasticsearch, memcache]`

It is crucial to understand that in PEBA honeypot data is devided in (1) *public community data* (everyone can contribute using T-Pot, submit and query data) and (2) data from *private domain honeypots* (e.g. those from DTAG) which can only be submitted and queried using distinct credentials. 

## **Implemented API endpoints:** 

***Public & Private PUT endpoint*** using authentication to deliver honeypot events using ewsposter. 

 - [POST] */ews-0.1/alert/postSimpleMessage* ==> takes the ews xml posted by ewsposter, processes and stores honeypot alerts in elasticsearch, flagged with domain.

The authentication can be done using either T-Pot community credentials (1) or distinct EWS user for the private domain (2). The username & token is stored in ewsposter's `ews.cfg` residing on T-Pot. Depending on the credentials, the data is flagged as community data (1) or private domain data (2).

***Private GET endpoints*** using authentication:

 - [POST] */alert/retrieveIPs* ==> returning the unique IP addresses of the last attacks in timeframe (default 120 minutes), a "Bad IP List". Can further be parametrized using out=json. Defaults to xml.
 - [POST] */alert/retrieveAlertsCyber* ==> returning the last 1000 attacks, including IPs.
 - [POST] */alert/querySingleIP* ==> returns last 1000 attacks from IP. Set IP in GET parameter "ip", e.g. */querySingleIP?ip=8.8.8.8*

The above private endpoints cannot be queried using the community credentials (1), only by users of the private domain (2).

***Public GET endpoints*** for Sicherheitstacho:
 
 - [GET] */alert/retrieveAlertsCount* ==> returns the number of attacks within timespan in minutes or since the beginning of the current day e.g. */retrieveAlertsCount?time=10* or */retrieveAlertsCount?time=day*. Can further be parametrized using *out=json*. Defaults to xml.  
 - [GET] */alert/heartbeat* ==> Returns backend elasticsearch and memcached status
 - [GET] */alert/retrieveAlertsJson* ==> Returns last 35 Alerts in json for usage in sicherheitstacho
 - [GET] */alert/datasetAlertsPerMonth* ==> Returns attacks per day for */datasetAlertsPerMonth?days=x* in the last x days OR for the last month, defaults to last month, if no GET parameter "days" is given
 - [GET] */alert/datasetAlertTypesPerMonth* ==> Returns attacks / day, grouped by honeypot type, for */datasetAlertTypesPerMonth?days=x* in the last x days OR for the last month, defaults to last month, if no GET parameter "days" is given
 - [GET] */alert/retrieveAlertStats* ==> Returns combines statistics in one call: AlertsLastMinute, AlertsLastHour, AlertsLast24Hours
 - [GET] */alert/topCountriesAttacks* ==> Returns information on the Top 10 attacker countries and top 10 attacked countries. use GET parameter "offset" and "topx" to determine the offset from this month (default: this month) and how many results shall be returned (default: top10)
 - [GET] */alert/retrieveLatLonAttacks* ==> Returns top X count on Lat and Lng. use GET parameter "offset" and "topx" to determine the offset from now in days (default: last 24h) and how many results shall be returned (default: top10). Use parameter "direction" to determine if source or destination location is given.
 - [GET] */alert/retrieveAlertsCountWithType* ==> returns the number of attacks within timespan in minutes or since the beginning of the current day, grouped by Type, e.g. */retrieveAlertsCountWithType?time=10* or */retrieveAlertsCountWithType?time=day*. Returns json.

 
**Data domain:**

By default, querying the above endpoints, data from the **T-Pot community honeypots** is returned. To retrieve data from the **private domain honeypots**, add a GET parameter *ci=0*. 

Example:  */alert/retrieveAlertsJson?ci=0* to retrieve the private json data feed. This works both on the public and private endpoints.

## **Setup:**

**Preconditions:** 

PEBA requires an installation of Elasticsearch (5.4 and 5.5 tested). 

**Installation:** (on Debian/Ubuntu)

	# install required packages
    sudo apt-get install python3 python3-dev python3-pip python3-pylibmc memcached
    
	# clone the repository 
    sudo git clone git@github.com:dtag-dev-sec/PEBA.git 
	cd PEBA
	
    # copy the config file to the required destination
    sudo mkdir -p /etc/ews/
	sudo cp etc/ews/peba.cfg /etc/ews/peba.cfg
	
	# install python3 requirements 
	pip3 install -r requirements.txt
    
    # download Maxmind's GeoIP database and copy it to the right destination
    cd var/lib/GeoIP/
	./download.sh
	sudo cp *.dat /var/lib/GeoIP/

*Note:*  When installing on MacOS, you need to install the following additional packets: 
`brew install libmemcached` and `pip3 install pylibmc`

For the next step, make sure that both Elasticsearch and memcached are running!

**Initializing the Index:**

Next, we need to create an Elasticsearch index for the alerts. You should edit the file `misc/setup-es-indices.py`to match the Elasticsearch host:port tuple and set your individual index names. If Elasticsearch is running on localhost, there is nothing to change here.

    python3 misc/setup-es-indices.py
       
The index name as well as the Elasticsearch connection parameters have to be reflected in */etc/ews/peba.cfg*.

**Adding users:**

Data can be submitted with the community credentials (as specified in `/etc/ews/peba.cfg`) and it will be added to the community domain. If you want to add data to the private domain or query one of the APIs above which require authentication,  users have to be added. In order to add users to the authentication pool, the script `./misc/add-user.py` can be used. It will ask you for a username and a password and add the user to the authentication index "users". You should at least have one user setup here. 

	python3 misc/add-user.py

You can safely ignore the last two questions in the script, as the are not yet implemented. ;) 

## **Configuration:**

By default, and if you have everything running on localhost, you do not need to modify the `/etc/ews/peba.cfg`. However, if your elasticsearch or memcache is running on another host, you may want to edit the configuration file. 

You should therefore check the following paramters and make sure they match your environment: ELASTICSEARCH_HOST, ELASTICINDEX, MEMCACHE. 

## **Running PEBA:**

**Testing PEBA:**

For testing, you can run the application via:

   	./start.sh
   	
The webapplication runs on port 9922. Running as shown above, PEBA logs errors to `./error.log`. However, running like this is not recommended in a production environment.


## **Deploying PEBA:**

In production environments PEBA needs a [reverse proxy](http://flask.pocoo.org/docs/0.12/deploying/wsgi-standalone/#proxy-setups) for SSL termination.

For convenience, the application can be deployed via ansible on a debian (tested: stretch) / ubuntu (tested 16.04) system and started using a systemd script. 

As mentioned before, PEBA relies on an Elasticsearch and memcache installation which needs to be configured separately. Having both up and running, adjust `ansible/hosts` with the correct paramters (hostname and following operational values), then deploy via:

    ./ansible/deploy.sh <prod|test>

This should take you from scratch to a running installation and automate PEBA deployments across multiple servers. 

If you don't want to use the ansible deployment you *can* also manually go through all the necessary steps, however, this is prone to errors and the above deployment is tested and working.

It would be something like this, **note that this is *not* tested**: 

		# add peba user to system
		sudo adduser --home=/nonexistent --system --shell=/bin/nologin peba
		
		# make directories
		sudo mkdir -p /opt/peba
		sudo mkdir -p /var/run/peba
		sudo mkdir -p /etc/ews
		
		# copy the peba scripts to the right location
		sudo cp peba.py putservice.py elastic.py communication.py requirements.txt /opt/peba
		
		# own peba directory 
		sudo chown -R peba /opt/peba
		
		# create logs and own them to peba
		sudo touch /var/log/peba/peba.log
		sudo touch /var/log/peba/peba_error.log
		sudo chown peba /var/log/peba/peba.log  /var/log/peba/peba_error.log
		
		# make sure the access rights are right for the peba folder
		sudo chmod -R peba /opt/peba		
		
		# copy the systemd service file
		sudo cp etc/systemd/system/peba.service /etc/systemd/system/peba.service 
		
		# don't forget to copy the config file - ONLY if you haven't already done it before
		# sudo mkdir -p /etc/ews/
		# sudo cp etc/ews/peba.cfg /etc/ews/peba.cfg

		
		# don't forget to install the pip3 requirements - ONLY if you haven't already done it
		#	pip3 install -r requirements.txt

		
		# ... and don't forget to copy the geoip files to /var/lib/GeoIP/ - ONLY if you haven't already done it
		# cd var/lib/GeoIP/
		# ./download.sh
		# sudo cp *.dat /var/lib/GeoIP/

		# enable service
		sudo systemctl enable peba.service
		
		# start peba
		sudo systemctl start peba.service


**Caching:**

As mentioned before, a caching mechanism has been implemented so GET requests to the API are cached by memcached. 

While running the [sicherheitstacho.eu](http://community.sicherheitstacho.eu) website, we encountered that still too many queries reached the backend and hence we decided to prefill the caches for the queries issued by the reactjs application. 
The script is located at `misc/fillcaches.py` and is tailored to our frontend using multiple caching servers on each node. This may be a good starting point for you if you also encounter caching problems and want to prefill the caches in use. 

**Configuration of ewsposter:**

When setting up your own backend for honeypot data collection, you need to change the submission url of ewsposter's `ews.cfg` in the `[EWS]`-section to whatever domain your backend is running on (`rhost_first` / `rhost_second`). Further, make sure your ewsposter's `ews.cfg` has matching community username and token as defined in `/etc/ews/peba.cfg`.

## **Development:**

Although the backend is tailored to fullfill our specific needs, we think it might be a good starting point for setting up your own centralized honeypot collection plattform. 

PEBA support will be handled same as with T-Pot, via Github issues. Please bear in mind that the software is developed in the spare time next to our main job. If you have any contributions you think could be beneficial for the project, feel free to submit pull requests. :) 


**Functional Tests:**

The basic functionality of the application's GET and a PUT service can be rudimentarily tested using `./misc/test-getService.sh` respectively `./misc/test-putService.sh` which will send corresponding requests to retrieve or store data. Again, prod and test instance can be tested, further community data or private (dtag honeypots) data can be retrieved (only GET). Change the config section in script according to your environment.

    ./misc/test-getService.sh <prod|test> <private|community>
    ./misc/test-putService.sh <prod|test>

For some of the above requests, you need a username & password in order to access the API. As described above, use the script `./misc/add-user.py` to add new users and replace the file username and token in `./misc/request.xml`. 


## **Credits**

Developed by André Vorbach (vorband)  &  Markus Schmall (schmalle).

Overall help, friendly extensions / comments / suggestions by Markus Schroer and Robin Verton. Valuable discussions with Aydin Kocas, Markus Schroer, Marco Ochse, Robin Verton and Rainer Schmidt.

**Frameworks / tools**:

[Maxmind GeoIP](https://dev.maxmind.com/geoip/legacy/geolite/) - Gunicorn - Flask - Elasticsearch - Memcached

**Thanks**:

Lutz Wischmann from [42, The Software architects](http://www.software-architects.de/) and all people from [The Honeynet Project](https://www.honeynet.org/)

## **Disclaimer**:

PEBA is published as it is without any liability as open source software. As with every piece of code, it may contain bugs. We will try to fix them as soon as we can verify the bugs, so please let us know when you find any. 


## **Misc**:

It would have taken at least 42 bottles of Club-Mate to support the development of PEBA. However, we ran out of supplies. ;) 
