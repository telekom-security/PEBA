#!/bin/bash 

# CONFIG:
TEST=http://127.0.0.1:9922
PROD=https://community.sicherheitstacho.eu:9443

if [ "$#" -ne 1 ]; then
    echo "invoke: $0 <test|prod>"
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
        echo "invoke: $0 <test|prod>"
       exit 1      
	;;
esac

echo "***** TESTING PUT WEBSERVICE"

echo "***** SENDING alarm.xml *****"
AUTH=./put-requests/alarm.xml
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH $BIND/ews-0.1/alert/postSimpleMessage
echo "***** END alarm.xml *****"
echo ""
sleep 3

echo "***** SENDING alarmcowrie.xml *****"
AUTH=./put-requests/alarmcowrie.xml
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH $BIND/ews-0.1/alert/postSimpleMessage
echo "***** END alarmcowrie.xml *****"
echo ""
sleep 3

echo "***** SENDING alarmdionaea.xml *****"
AUTH=./put-requests/alarmdionaea.xml
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH $BIND/ews-0.1/alert/postSimpleMessage
echo "***** END alarmdionaea.xml *****"
echo ""
sleep 3

echo "***** SENDING alarmht.xml *****"
AUTH=./put-requests/alarmht.xml
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH $BIND/ews-0.1/alert/postSimpleMessage
echo "***** END alarmht.xml *****"
echo ""
sleep 3

echo "***** SENDING alarmsuricata.xml *****"
AUTH=./put-requests/alarmsuricata.xml
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH $BIND/ews-0.1/alert/postSimpleMessage
echo "***** END alarmsuricata.xml *****"
echo ""
sleep 3

echo "***** SENDING broken.xml *****"
AUTH=./put-requests/broken.xml
curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH $BIND/ews-0.1/alert/postSimpleMessage
echo "***** END broken.xml *****"
echo ""
sleep 3

echo "***** END TESTING PUT WEBSERVICE"
