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
failed=false

for i in $(ls put-requests/*.xml); do 
    echo "***** SENDING $i *****"
    PAYLOAD=./put-requests/alarm.xml
    res=$(curl -s -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$PAYLOAD $BIND/ews-0.1/alert/postSimpleMessage)
    if $(echo $res|grep -iqF ok); 
    then
      echo $res
    else
      failed=true 
      echo $res|egrep --color "\b(OK|failed)\b|$"
    fi
    echo "***** END $i *****"
done

RESTORE='\033[0m'

RED='\033[00;31m'
GREEN='\033[00;32m'

if $failed;
then
  echo -e "${RED}***** ERROR DETECTED ***** ${RESTORE} "
else
  echo -e "${GREEN}***** EVERYTHING SUCCESSFULLY SUBMITTED ***** ${RESTORE} "
fi
