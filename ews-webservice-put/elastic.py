import requests
import xml.etree.ElementTree as xmlParser
from xml.etree.ElementTree import tostring
import pygeoip
from geoip import geolite2
import hashlib

from elasticsearch import Elasticsearch


def putAlarm(host, index, sourceip, destinationip, createTime):

    gi = pygeoip.GeoIP("/var/lib/GeoIP/GeoIP.dat")
    giASN = pygeoip.GeoIP('/var/lib/GeoIP/GeoIPASNum.dat')

    m = hashlib.md5()
    m.update((createTime + sourceip + destinationip).encode())

    alert = {
              "country": gi.country_code_by_addr(sourceip),
            "vulnid": "DUMMY",
            "originalRequestString": "/cgi-bin/.br/style.css2/2",
            "esid": "DUMMY",
            "sourceEntryAS": giASN.org_by_addr(sourceip),
            "createTime": createTime,
            "clientDomain": "d",
            "peerIdent": "MSTest3",
            "locationString": "51.0, 9.0",
            "client": "-",
            "location": "51.0, 9.0",
            "sourceEntryIp": sourceip,
            "additionalData": "host: www.webe.de; sqliteid: 3688; ",
            "peerType": "null",
            "targetEntryIp": destinationip
        }


    es = Elasticsearch(host)
    res = es.index(index=index, doc_type='Alert', id=m.hexdigest(), body=alert)




    return 0

def queryAlerts(server, index, maxAlerts):
    xml = """{
  "sort": {
    "createTime": {
      "order": "desc"
    }
  }
}"""

    returnData = ""

    url = server + ":9200/" + index + "/Alert/_search"

    headers = {'Content-Type': 'application/xml'}  # set what your server accepts

    response = requests.post(url, data=xml, headers=headers).text

#    jsonData = response.json()

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
