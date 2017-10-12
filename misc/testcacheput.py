from flask import Flask, request, abort, jsonify, Response

import elastic
from werkzeug.contrib.cache import MemcachedCache


cache = MemcachedCache()

(lat, long, country, asn, countryName) = elastic.getGeoIP("127.0.0.1", cache)
print("Lat: " + str(lat) + " Long:" + str(long) + " Country:" + country + " ASN: " + asn + " CountryName:" + countryName)

(lat, long, country, asn, countryName) = elastic.getGeoIP("128.65.210.186", cache)
print("Lat: " + str(lat) + " Long:" + str(long) + " Country:" + country + " ASN: " + asn + " CountryName:" + countryName)



