# PEBA - Python EWS Backend API

Small backend application to offer an API alternative for current EWS backend, e.g. for the T-Pot Community backend. 

**Currently implemented functions:** 

 - */alert/retrieveIPs* ==> returning the unique IP addresses of the last attacks. 
 - */alert/retrieveAlertsCyber* ==> returning the last 1000 attacks. 


**Install requirements:**

    pip install -r requirements.txt 



***Note:***
	
`pip install -r requirements.txt`  may fail for *hashlib* (known bug). 

Use `easy_install hashlib` to resolve this issue. 

**Run Application:**

   	./start.sh


The webapplication runs on port 8000. It needs a [reverse proxy](http://flask.pocoo.org/docs/0.12/deploying/wsgi-standalone/#proxy-setups)  for SSL termination. 


The application can be tested using `./misc/test.sh` which will send the appropriate request to retrieve data.


You need corresponding WSUser username & token to access the API. Replace them in `./misc/request.xml`
