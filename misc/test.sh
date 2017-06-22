#!/bin/bash 
echo "***** TESTING LOCAL WEBSERVICE" 
echo "***** ALERTS *****"
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./request.xml http://127.0.0.1:8000/alert/retrieveAlertsCyber
echo "***** END ALERTS *****"
echo ""
echo "***** IPS *****"
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./request.xml http://127.0.0.1:8000/alert/retrieveIPs
echo ""
echo "***** END IPS *****"
echo "" 
echo "***** END TESTING LOCAL WEBSERVICE"

