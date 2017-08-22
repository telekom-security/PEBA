#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
    echo "invoke: $0 <test|prod>"
    exit 1
fi

case "$1" in
    test)
        echo "Deploying on Test-Server"
        ansible-playbook -i ./hosts ewsbackend-test.yml
      ;;
    prod)
        echo "Deploying on Prod-Server"
        ansible-playbook -i ./hosts ewsbackend-prod.yml
      ;;
    *)
       echo "invoke: $0 <test|prod>"
      ;;
esac
exit 0
