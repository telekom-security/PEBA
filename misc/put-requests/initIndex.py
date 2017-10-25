from elasticsearch import Elasticsearch

host = "127.0.0.1"
port = 9200
index = "ews2017.1"

es = Elasticsearch([{'host': host, 'port': 9200}])

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
                },
                "recievedTime": {
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                },
                "sourceEntryIp": {
                    "type": "ip"
                },
                "targetEntryIp": {
                    "type": "ip"
                },
                "clientDomain": {
                    "type": "boolean"
                },
                "externalIP": {
                    "type": "ip"
                },
                 "internalIP": {
                    "type": "ip"
                },
                 "hostname": {
                    "type": "text"
                }
            }
        },
        "CVE": {
            "properties": {
                "firstSeen": {
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                },
                "lastSeen": {
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis"
                },
                "firstIp": {
                    "type": "ip"
                },
                "number": {
                    "type": "text"
                }

            }
        },

        "IP": {
            "properties": {
                "ip": {
                    "type": "ip"
                },
                "longitude": {
                    "type": "text"
                },
                "latitude": {
                    "type": "text"
                },
                "country": {
                    "type": "text"
                },
                "asn": {
                    "type": "text"
                },
                "countyname": {
                    "type": "text"
                }

            }
        }

    }
}
# create index
es.indices.create(index=index, ignore=400, body=settings)
