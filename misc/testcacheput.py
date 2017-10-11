from flask import Flask, request, abort, jsonify, Response

import elastic
from werkzeug.contrib.cache import MemcachedCache


cache = MemcachedCache()

(lat, long, country, asn, countryName, latDest, longDest, countryTarget, asnTarget, countryTargetName) = elastic.getGeoIP("127.0.0.1", "193.99.144.85", cache)
print("Lat: " + str(latDest) + " Long:" + str(longDest) + " Country:" + countryTarget + " ASN: " + asnTarget + " CountryName:" + countryTargetName)



