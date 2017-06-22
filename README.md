# PEBA - Python EWS Backend API

Small backend application to offer an API alternative for current EWS backend. 

**Currently implemented functions:** 

 - */alert/retrieveAlertsCyber* ==> returning the *unique* IP addresses of the last 1000 alerts. 


**Install requirements:**

    pip install -r requirements.txt 



***Note:***
	
`pip install -r requirements.txt`  may fail for *hashlib* (known bug). Use `easy_install hashlib` to resolve this issue. 

**Run Application:**

    gunicorn webservice:app -w 4 -b 127.0.0.1


The webapplication runs on port 8000. It needs a [reverse proxy](http://flask.pocoo.org/docs/0.12/deploying/wsgi-standalone/#proxy-setups)  for SSL termination. 


The application can be tested using `./misc/test.sh` which will send the appropriate request to retrieve data.


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
