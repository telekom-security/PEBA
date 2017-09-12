#!/usr/bin/env bash


rm Geo*.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
gunzip GeoLiteCity.dat.gz
gunzip GeoIP.dat.gz
gunzip GeoIPASNum.dat.gz


