
from pymongo import MongoClient, errors
import hashlib

#
# default credentials for community
#

username = "community-01-user"
password = "foth{a5maiCee8fineu7"

#
# Extract username and password from request
#
def extractAuth(tree):

    usernameFromRequest = ""
    passwordFromRequest = ""

    for node in tree.findall('.//Authentication'):

        for child in node:

            childName = child.tag

            if (childName == "token"):
                passwordFromRequest = child.text

            if (childName == "username"):
                    usernameFromRequest = child.text

    return usernameFromRequest, passwordFromRequest


#
# Check if community login
#
def handleCommunityAuth(usernameFromRequest, passwordFromRequest):

    return (username == usernameFromRequest) and (password == passwordFromRequest)

def checkPrivateIP(ip):
    return 0


# Authenticate user in mongodb
def authenticate(username, token, mongohost, mongoport):
    client = MongoClient(mongohost,  int(mongoport))
    db = client.ews
    try:
        dbresult = db.WSUser.find_one({'peerName': username})
        if dbresult == None:
            return False
        else:
            tokenhash = hashlib.sha512(token)
            if dbresult['token'] == tokenhash.hexdigest():
                    return True
            else:
                return False
    except errors.ServerSelectionTimeoutError as err:
        print('MongoDB cannot be reached: %s' %  err)
        return False