
#!/bin/bash 

BIND=127.0.0.1:9922
AUTH=request.xml

echo "***** TESTING LOCAL WEBSERVICE" 

echo "***** RETRIEVEALERTCYBER *****"
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH http://$BIND/alert/retrieveAlertsCyber
echo "***** END RETRIEVEALERTSCYBER *****"
echo ""
sleep 3

echo "***** RETRIEVEIPS *****"
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH http://$BIND/alert/retrieveIPs
echo ""
echo "***** END RETRIEVEIPS *****"
echo ""
sleep 3   

echo "***** RETRIEVEALERTCOUNT XML  *****"
curl http://$BIND/alert/retrieveAlertsCount?time=10
echo "***** END RETRIEVEALERTCOUNT XML  *****"
echo ""
sleep 3

echo "***** RETRIEVEALERTCOUNT JSON  *****"
curl "http://$BIND/alert/retrieveAlertsCount?time=10&out=json"
sleep 3
echo "***** END RETRIEVEALERTCOUNT  JSON *****"
echo ""
sleep 3

echo "***** HEARTBEAT  *****"
curl http://$BIND/heartbeat
echo "" 
echo "***** END HEARTBEAT  *****"
echo ""
sleep 3

echo "***** RETRIEVEALERTJSON  *****"
curl http://$BIND/alert/retrieveAlertsJson
echo "***** END RETRIEVEALERTJSON  *****"
echo "" 

echo "***** RETRIEVEALERTTSPERMONTH  *****"
curl http://$BIND/alert/datasetAlertsPerMonth
echo "***** END RETRIEVEALERTJSON  *****"
echo ""



echo "***** END TESTING LOCAL WEBSERVICE"

