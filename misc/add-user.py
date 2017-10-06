# !/usr/bin/env python
# -*- coding: utf-8 -*-

'''

Script to add a user to 'users' index
v.01

'''

from elasticsearch import Elasticsearch
import hashlib
import re

es = Elasticsearch()
username, token, tokenInput, email, getonly, community = "", "","", "ex@ample.com", False, False
newIndex=False

# check if 'users' index exists, otherwise create index

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

if not es.indices.exists("users"):
    res = es.indices.create(index = 'users', body = request_body, ignore=400)
    newIndex=True

# gather user information

print(chr(27) + "[2J")
print("******************************************")
print("Add new user to ES users index.")
print("******************************************")

# input username
usernameInput = input("Enter Username: ")
username=usernameInput.replace(" ", "_")

# check if user exists
if not newIndex:
    res = es.search(index='users', body={
                  "query": {
                    "term": {
                      "peerName.keyword": username
                    }
                  }
                })
    if res["hits"]["total"] > 0:
        print("User '"+ username + "' already exists in index. Choose a different username or delete _id : '" + str(res['hits']['hits'][0]['_id'])  + "'. Aborting.")
        exit(1)

# input password
tokenInput = input("Enter Password: ")
token = hashlib.sha512(tokenInput.encode('utf-8')).hexdigest()

# input email
emailInput = input("Enter Email: ")
if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", emailInput) != None:
    email=emailInput
else:
    print("Invalid email address. Bye.")
    exit(1)

# input getOnly
getonlyInput = input("Is this user 'read only' who cannot submit data? (y/N): ")
if getonlyInput.lower() == "y":
    getonly = True

# input getOnly
communityInput = input("Can this user only access 'community data'? (y/N): ")
if communityInput.lower() == "y":
    community = True


print("")
print("You entered:")
print("**************")
print("Username: " + username)
print("Password: " + tokenInput)
print("Email: " + email)
print("getOnly: " + str(getonly))
print("community: " + str(community))
print("**************")
print("")

correctInput = input("Is the above correct? (y/N)")
if correctInput.lower() != "y":
    print("Ok, rerun script and reenter it.")
    exit(1)
print("OK, adding to ES.")

entry = {
    'peerName': username,
    'token': token,
    'getOnly': getonly,
    'community': community,
    'email': email
}

# add user
res = es.index(index="users", doc_type='wsUser', body=entry)
print("New user submission successful?:" + str(res['created']))

