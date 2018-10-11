
#!/bin/bash 

# CONFIG:
TEST=http://127.0.0.1:9922
PROD=https://community.sicherheitstacho.eu:9443
AUTH=./get-requests/request.av.xml

# List all public and private endpoints and determine how much output to show
# format: 
# url : lines of data to display

privateEndpoints=(
  "/alert/retrieveAlertsCyber?topx=3&$DOM":34
  "/alert/retrieveIPs?$DOM":18
  "/alert/retrieveIPs15m?out=json&$DOM":21
  "/alert/retrieveIPs15m?out=xml&$DOM":22
  "/alert/querySingleIP?ip=5.39.217.84&$DOM":30
  )

publicEndpoints=(
  "/alert/retrieveAlertsCount?time=10&":100
  "/alert/retrieveAlertsCount?time=10&out=json&":100
  "/heartbeat":100
  "/alert/retrieveAlertsJson?":50
  "/alert/datasetAlertsPerMonth?":100
  "/alert/datasetAlertTypesPerMonth?":1000
  "/alert/retrieveAlertStats?":100
  "/alert/topCountriesAttacks?offset=1&topx=4&":100
  "/alert/retrieveLatLonAttacks?offset=3&direction=src&":100
  "/alert/retrieveAlertsCountWithType?time=10&":100
  "/alert/TpotStats?day=20181008&":100

)

if [ "$#" -ne 2 ]; then
    echo "invoke: $0 <test|prod> <private|community|all>"
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
    all)
        DOM="ci=-1"
        echo "Testing all domains data."
      ;;
    *)
        echo "invoke: $0 <test|prod> <private|community>"
        exit 1
	;;
esac

echo '\033[00;33m'"***** TESTING GET WEBSERVICE PUBLIC ENDPOINTS"'\033[0m'

for i in ${publicEndpoints[@]}; 
do 
  length=$(echo $i|cut -d ":" -f 2)
  url=$(echo $i|cut -d ":" -f 1)
  domain=$BIND$url
  if [ "${url: -1}" == "&" ] || [ "${url: -1}" == "?" ] 
  then
    domain=$domain$DOM
  fi  
  echo '\033[00;33m'"***** TESTING $domain *****"'\033[0m'
  curl -s "$domain" | head -$length
  echo "***** END RESULT *****\n\n"
  #sleep 1
done

exit 1



echo '\033[00;33m'"***** TESTING POST WEBSERVICE PRIVATE ENDPOINTS"'\033[0m'

for i in ${privateEndpoints[@]}; 
do 
  length=$(echo $i|cut -d ":" -f 2)
  url=$(echo $i|cut -d ":" -f 1)
  domain=$BIND$url
  if [ "${url: -1}" == "&" ] || [ "${url: -1}" == "?" ] 
  then
    domain=$domain$DOM
  fi
  echo '\033[00;33m'"***** TESTING $domain *****"'\033[0m'
  curl  -s -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./$AUTH "$domain" |head -$length;
  echo "***** END RESULT *****\n\n"
  # sleep 1

done

echo '\033[00;33m'"***** END TESTING WEBSERVICE ENDPOINTS"'\033[0m'
exit 0
