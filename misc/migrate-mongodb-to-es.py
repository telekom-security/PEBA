#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''

Script to migrate existing mongodb users to elasticsearch
v.01

'''

from pymongo import MongoClient, errors
from elasticsearch import Elasticsearch

client = MongoClient('localhost', 27017)
es = Elasticsearch()

db = client.ews
wsUser = db.WSUser
bulk_data = []
host = "127.0.0.1"
port = 9200
index = "users"
eshost = "192.168.1.64"

for indexpos, user in enumerate(wsUser.find({}, {"peerName": 1, "token": 1})):

   data={}
   data={
       'peerName' : user['peerName'],
       'token' : user['token'],
       'getOnly' : False,
       'community' : False,
       'email' : 'ex@amle.com',
   }
   metadata = {
       "index": {
           "_index": index,
           "_type": "wsUser",
           "_id": indexpos
       }
   }
   bulk_data.append(metadata)
   bulk_data.append(data)



es = Elasticsearch([{'host': host, 'port': 9200}])

request_body = {
    "settings" : {
        "number_of_shards": 1,
        "number_of_replicas": 1
    },
    "mappings": {
        "wsUser": {
            "properties": {
                "peerName": {
                    "type": "text"
                },
                "token": {
                    "type": "text"
                },
                "getOnly": {
                    "type": "boolean"
                },
                "community": {
                    "type": "text"
                ,
                "email": {
                    "type": "text"
                }
            }
        }
    }
}
}

#print(bulk_data)

if es.indices.exists(index):
    print("Deleting index '%s'" % (index))
    res = es.indices.delete(index = index)
    print("Result: '%s'" % (res))

print("Creating new index: '%s'" % (index))
res = es.indices.create(index = index, body = request_body, ignore=400)
print("Result: '%s'" % (res))

print("Adding Data to index")
res = es.bulk(index = index, body = bulk_data, refresh = True)

print("Checking if Data is in index")
res = es.search(index = index, size=2, body={"query": {"match_all": {}}})
print("Result: '%s'" % (res))
