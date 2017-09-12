
#!/bin/bash 

# CONFIG:
TEST=http://127.0.0.1:9922
PROD=https://community.sicherheitstacho.eu:9443
AUTH=./get-requests/request.xml



if [ "$#" -ne 2 ]; then
    echo "invoke: $0 <test|prod> <private|community>"
    exit 1
fi

case "$1" in
    test)
        BIND=$TEST
        echo "Testing with Test-Server $BIND"
      ;;
    prod)
        BIND=$PROD
        echo "Testing with Prod-Server $BIND"
      ;;
    *)
        echo "invoke: $0 <test|prod> <private|community>"
       exit 1      
	;;
esac

case "$2" in
    private)
        DOM="ci=0"
        echo "Testing private domain data."
      ;;
    community)
        DOM="ci=1"
        echo "Testing community domain data."
      ;;
    *)
        echo "invoke: $0 <test|prod> <private|community>"
        exit 1
	;;
esac



echo "***** TESTING GET WEBSERVICE"

echo "***** RETRIEVEALERTCYBER *****"
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH $BIND/alert/retrieveAlertsCyber?$DOM
echo "***** END RETRIEVEALERTSCYBER *****"
echo ""
sleep 3

echo "***** RETRIEVEIPS *****"
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH $BIND/alert/retrieveIPs?$DOM
echo ""
echo "***** END RETRIEVEIPS *****"
echo ""
sleep 3   

echo "***** RETRIEVEALERTCOUNT XML  *****"
curl "$BIND/alert/retrieveAlertsCount?time=10&$DOM"
echo "***** END RETRIEVEALERTCOUNT XML  *****"
echo ""
sleep 3

echo "***** RETRIEVEALERTCOUNT JSON  *****"
curl "$BIND/alert/retrieveAlertsCount?time=10&out=json&$DOM"
sleep 3
echo "***** END RETRIEVEALERTCOUNT  JSON *****"
echo ""
sleep 3

echo "***** HEARTBEAT  *****"
curl "$BIND/heartbeat"
echo "" 
echo "***** END HEARTBEAT  *****"
echo ""
sleep 3

echo "***** RETRIEVEALERTJSON  *****"
curl "$BIND/alert/retrieveAlertsJson?$DOM"
echo "***** END RETRIEVEALERTJSON  *****"
echo "" 
sleep 3

echo "***** RETRIEVEALERTSPERMONTH  *****"
curl "$BIND/alert/datasetAlertsPerMonth?$DOM"
echo "***** END RETRIEVEALERTSPERMONTH  *****"
echo ""
sleep 3 

echo "***** RETRIEVEALERTTYPESSPERMONTH  *****"
curl "$BIND/alert/datasetAlertTypesPerMonth?$DOM"
echo "***** END RETRIEVEALERTYPESPERMONTH  *****"
echo ""
sleep 3

echo "***** RETRIEVEALERTSTATS  *****"
curl "$BIND/alert/retrieveAlertStats?$DOM"
echo "***** END RETRIEVEALERTSTATS  *****"
echo ""
sleep 3

echo "***** RETRIEVETOPCOUNTRIES  *****"
curl "$BIND/alert/topCountriesAttacks?offset=1&topx=4&$DOM"
echo "***** END RETRIEVETOPCOUNTRIES *****"
echo ""
sleep 3

echo "***** RETRIEVELATLONG  *****"
curl "$BIND/alert/retrieveLatLonAttacks?offset=3&topx=4&direction=src&$DOM"
echo "***** END RETRIEVELATLONG *****"
echo ""
sleep 3

echo "***** RETRIEVEALERTCOUNTWITHTYPE  *****"
curl "$BIND/alert/retrieveAlertsCountWithType?time=10&$DOM"
echo "***** END RETRIEVEALERTCOUNTWITHTYPE *****"
echo ""
sleep 3


echo "***** END TESTING GET WEBSERVICE"
exit 0
