
'''


'''

from elasticsearch import Elasticsearch, ElasticsearchException

import base64

import hashlib
es = Elasticsearch(["127.0.0.1:9000"])

checksumssha256 = {'DEADBEEF': 0}
checksumsfuzzy = {'DEADBEEF': 0}

counter, duplicatessha256, uniquessha256, duplicatesfuzzy, uniquesfuzzy = 0, 0, 0, 0, 0;

res = es.search(index="packets", body={"query":{"bool":{"must":[{"match_all":{}}],"must_not":[],"should":[]}},"from":0,"size":2000,"sort":[],"aggs":{}})
print("Got %d Hits:" % res['hits']['total'])

for hit in res['hits']['hits']:
    data = hit["_source"]["data"].encode('utf-8')
    data = base64.b64decode(data)
    print(data)

    m = hashlib.sha256()
    m.update(data.lower())

    hash = m.hexdigest()

    counterForHash = checksumssha256.get(hash, 0)
    if (counterForHash == 0):
        uniquessha256 += 1
        checksumssha256[hash] = 1
    else:
        checksumssha256[hash] = counterForHash + 1
        duplicatessha256 += 1

    if (b'Host:' in data):

        start = data.find(b"Host:") + 5
        end = data.find(b"\"", start)

        print("Host found: ",start, end)

        cleanedData = data[0:start] + data[end:len(data)]


        m = hashlib.sha256()
        m.update(cleanedData.lower())

        hash = m.hexdigest()

        counterForHash = checksumsfuzzy.get(hash, 0)
        if (counterForHash == 0):
            uniquesfuzzy += 1
            checksumsfuzzy[hash] = 1
        else:
            checksumsfuzzy[hash] = counterForHash + 1
            duplicatesfuzzy += 1

    else:
        print("Host not found")






print("Statistics: ")
print(" ")
print("Uniques (sha256): ", uniquessha256)
print("Duplicates (sha256): ", duplicatessha256)

print(" ")
print("Fuzzy results for HTTP requests")
print("Uniques (fuzzy): ", uniquesfuzzy)
print("Duplicates (fuzzy): ", duplicatesfuzzy)

