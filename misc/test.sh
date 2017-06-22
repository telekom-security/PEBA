#!/bin/bash 
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./request.xml http://127.0.0.1:5000/alert/retrieveAlertsCyber 


