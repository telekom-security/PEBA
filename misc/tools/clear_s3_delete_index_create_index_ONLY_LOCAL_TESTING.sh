#!/bin/bash
clear
echo "WARNING!!!!"
echo "THIS WILL DELETE THE ENTIRE S3 STORAGE AND INDICES!!!! ONLY USE FOR LOCAL TESTING!!!"
read -r -p "Are you sure? [y/N] " response
case "$response" in
    [yY][eE][sS]|[yY])
        delete_indices
        ;;
    *)
        echo "Abort!"
        exit 0
        ;;
esac


# clear s3 storage 
s3cmd rm --force --recursive s3://artefacts/

# remove indices

curl -XDELETE "http://localhost:9200/packets"
curl -XDELETE "http://localhost:9200/ewscve"
curl -XDELETE "http://localhost:9200/ews-notifications"
curl -XDELETE "http://localhost:9200/ews2017.1"

python3 ../setup-es-indices.py
