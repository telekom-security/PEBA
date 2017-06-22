# PEBA - Python EWS Backend API

Small backend application to offer an API alternative for current EWS backend. 

Currently implemented function: 

 - */alert/retrieveAlertsCyber* ==> returning the *unique* IP addresses of the last 1000 alerts. 


The webapplication runs on port 5000. It needs a reverse proxy (e.g. nginx) for SSL termination.


Running the application: 

**Install requirements: **

    pip install -r requirements.txt 



***Note: ***
	
`pip install -r requirements.txt`  may fail for hashlib (known bug). Use `easy_install hashlib` to resolve this issue. 

**Start Flask:**

    export FLASK_APP=wenbservice.py
    flask run

The application can be tested using `./misc/test.sh` which will send the appropriate reuqest to retrieve data. 


You need corresponding WSUser username & token to access the API. Replace them in `./misc/request.xml`

The result will *hopefully* look as expected.

        <?xml version="1.0" encoding="UTF-8"?><EWSSimpleIPInfo>
          <Sources>
            <Source>
              <Address>193.99.144.95</Address>
            </Source>
            <Source>
              <Address>192.168.8.1</Address>
            </Source>
          </Sources>
        </EWSSimpleIPInfo>