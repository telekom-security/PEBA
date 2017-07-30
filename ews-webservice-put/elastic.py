import xml.etree.ElementTree as xmlParser
from xml.etree.ElementTree import tostring
import pygeoip
from geoip import geolite2
import hashlib

from elasticsearch import Elasticsearch


def getGeoIP(sourceip, destinationip):

    gi = pygeoip.GeoIP("/var/lib/GeoIP/GeoIP.dat")
    giCity = pygeoip.GeoIP("/var/lib/GeoIP/GeoCity.dat")
    giASN = pygeoip.GeoIP('/var/lib/GeoIP/GeoIPASNum.dat')


    try:
        lat = giCity.record_by_addr(sourceip)['latitude']
        long = giCity.record_by_addr(sourceip)['longitude']
        country = gi.country_code_by_addr(sourceip)
        asn = giASN.org_by_addr(sourceip)
        asnTarget = giASN.org_by_addr(destinationip)
        countryTarget = gi.country_code_by_addr(destinationip)
        return (lat, long, country, asn, asnTarget, countryTarget)

    except:

        print ("Failure at creating GeoIP information")
        return ("", "", "", "", "", "")



def initIndex(host, index):

    es = Elasticsearch([{'host': host, 'port': "9200"}])

    # index settings
    settings = {
        "settings": {
            "number_of_shards": 5,
            "number_of_replicas": 1
        },
        "mappings": {
            "Alert": {
                "properties": {
                    "createTime": {
                        "type": "date",
                        "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                    }
                }
            }
        }
    }
    # create index
    es.indices.create(index=index, ignore=400, body=settings)


def putAlarm(host, index, sourceip, destinationip, createTime, tenant, url, analyzerID, peerType):

    try:



        m = hashlib.md5()
        m.update((createTime + sourceip + destinationip).encode())

        (lat, long, country, asn, asnTarget, countryTarget) = getGeoIP(sourceip,destinationip)

        alert = {
                "country": country,
                "vulnid": "-",
                "originalRequestString": url,
                "sourceEntryAS": asn,
                "createTime": createTime,
                "clientDomain": tenant,
                "peerIdent": analyzerID,
                "peerType": peerType,
                "client": "-",
                "location": str(lat) + " , " + str(long),
                "sourceEntryIp": sourceip,
                "additionalData": "",
                "targetEntryIp": destinationip,
                "targetCountry": countryTarget,
                "targegEntryAS": asnTarget,
                "username": "",
                "password": "",
                "targetport": ""

            }


        es = Elasticsearch(host)
        res = es.index(index=index, doc_type='Alert', id=m.hexdigest(), body=alert)
        return 0

    except:

        print ("Error when persisting")
        return 1



def queryAlerts(server, index, maxAlerts):
    xml = """{
  "sort": {
    "createTime": {
      "order": "desc"
    }
  }
}"""

    returnData = ""

    es = Elasticsearch()

    res = es.search(index=index, doc_type="Alert", body={"query": {"match_all": {}}})

    print("Got %d Hits:" % res['hits']['total'])

    EWSSimpleAlertInfo = xmlParser.Element('EWSSimpleAlertInfo')
    alerts = xmlParser.SubElement(EWSSimpleAlertInfo, "Alerts")

    for hit in res['hits']['hits']:

        requestString = "%(originalRequestString)s " % hit["_source"]
        print("%(originalRequestString)s " % hit["_source"])

        alert = xmlParser.SubElement(alerts, "Alert")
        requestXML = xmlParser.SubElement(alert, "Request")
        requestXML.text = requestString

    returnData = tostring(EWSSimpleAlertInfo)

    return returnData
