from elasticsearch import Elasticsearch, ElasticsearchException
import ipaddress
import datetime
import base64
from dateutil.relativedelta import relativedelta
import botocore.session, botocore.client
from botocore.exceptions import ClientError
import hashlib
import os,sys
import json



s3session = botocore.session.get_session()
s3session.set_credentials(os.environ.get('S3AWSACCESSKEYID'), os.environ.get('S3AWSSECRETACCESSKEY'))
s3client = s3session.create_client(
        's3',
        endpoint_url=os.environ.get('S3ENDPOINT')
)

es = Elasticsearch(
        ['192.168.1.213'],
        port=9200
)

esindex="packets"


def retrieve_md5(page):
    #print(json.dumps(page, indent=4, sort_keys=True))
    #print(json.dumps(page['hits']['hits'], indent=4, sort_keys=True))

    for i in (page['hits']['hits']):
        hash=i['_source']['hash']
        data=i['_source']['data']
        print("hash: %s" % (hash))
        upload_hash(hash, data)

def upload_hash(hash,data):
    try:
        # upload file to s3
        bodydata = base64.decodebytes(data.encode('utf-8'))
        s3client.put_object(Bucket="artefacts", Body=bodydata, Key=hash)
        print('Storing file ({0}) using s3 bucket "{1}" on {2}'.format(
                hash, "artefacts", os.environ.get('S3ENDPOINT')))

    except ClientError as e:
        print("Received error: %s", e.response['Error']['Message'])

# get the entries from index.

# create scroll context
body={
  "query": {
    "bool": {
      "must": [
        {
          "match_all": {}
        }
      ]
    }
  },
  "_source": [
    "hash",
    "data"
  ]
}
page=es.search(index=esindex, body=body, scroll='2m', size=1000)
sid = page['_scroll_id']
scroll_size = page['hits']['total']
retrieve_md5(page)


#sys.exit(1)
while (scroll_size > 0):
    page = es.scroll(scroll_id=sid, scroll='2m')
    sid = page['_scroll_id']
    scroll_size = len(page['hits']['hits'])
   # print("scroll size: " + str(scroll_size))
    retrieve_md5(page)

