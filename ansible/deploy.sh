#!/usr/bin/env bash


case "$1" in
    test)
        echo "Deploying on Test-Server"
        ansible-playbook -i ./hosts ./roles/ewsbackend-test.yml
      ;;
    prod)
        echo "Deploying on Prod-Server"
        ansible-playbook -i ./hosts ./roles/ewsbackend-prod.yml
      ;;
    update-test)
        echo "Updating source on Test-Server"
        ansible-playbook -i ./hosts ./roles/ewsbackend-test-update.yml
      ;;
    update-prod)
        echo "Updating source on Prod-Server"
        ansible-playbook -i ./hosts ./roles/ewsbackend-prod-update.yml
      ;;
    *)
    echo "*****************************************************"
	echo "Please specify where you want to deploy. Options are:"
    echo " - test"
    echo " - prod"
    echo " - update-test"
    echo " - update-prod"
    echo "Invoke: $0 <test|prod|update-test|update-prod>"
    echo "*****************************************************"
      ;;
esac
exit 0
