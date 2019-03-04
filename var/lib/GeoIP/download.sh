#!/usr/bin/env bash


rm Geo*.gz
rm Geo*.mmdb

wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz
wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz

tar xf GeoLite2-City.tar.gz && mv ./GeoLite2-City_????????/GeoLite2-City.mmdb . && rm GeoLite2-City.tar.gz && rm -r ./GeoLite2-City_????????
tar xf GeoLite2-ASN.tar.gz && mv ./GeoLite2-ASN_????????/GeoLite2-ASN.mmdb . && rm GeoLite2-ASN.tar.gz && rm -r ./GeoLite2-ASN_????????
tar xf GeoLite2-Country.tar.gz && mv ./GeoLite2-Country_????????/GeoLite2-Country.mmdb . && rm GeoLite2-Country.tar.gz && rm -r ./GeoLite2-Country_????????
