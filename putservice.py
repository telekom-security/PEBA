# PUT functions

peerIdents = ["WebHoneypot", "Webpage",
              "Dionaea", "Network(Dionaea)",
              "honeytrap", "Network(honeytrap)",
              "kippo", "SSH/console(cowrie)",
              "cowrie", "SSH/console(cowrie)",
              "glastopf", "Webpage", ".gt3",
              "Webpage",".dio", "Network",
              ".kip", "SSH/console",
              "", ""]

def getPeerType(id):
    """
        parse through the data tables
    """
    for i in range (0,len(peerIdents) - 2, 2):
         honeypot = peerIdents[i]
         peerType = peerIdents[i+1]

         if (honeypot in id):
             return peerType

    return "Unclassified"


def fixUrl(destinationPort, url, peerType):
    """
        fixes the URL (original request string)
    """
    if ("honeytrap" in peerType):
        return "Attack on port " + str(destinationPort)

    return url

def handleAlerts(tree, tenant):
    """
        handle the Alerts
    """
    counter = 0
    for node in tree.findall('.//Alert'):
        # default values
        peerType, vulnid, sourcePort, destination, destinationPort, createTime, url, analyzerID, username, password, loginStatus, version, starttime, endtime = "Unclassified", "", "", "", "", "-", "", "", "", "", "", "", "", ""
        for child in node:
            childName = child.tag

            if (childName == "Analyzer"):
                id = child.attrib.get('id')
                peerType = getPeerType(id)

            if (childName == "Source"):
                source = child.text.replace('"', '')
                sourcePort = child.attrib.get('port')

            if (childName == "CreateTime"):
                createTime = child.text

            if (childName == "Target"):
                destination = child.text.replace('"', '')
                destinationPort = child.attrib.get('port')

            if (childName == "Request"):
                type = child.attrib.get('type')

                if (type == "url"):
                    url = urllib.parse.unquote(child.text)

                # if peertype could not be identified by the identifier of the honeypot, try to use the
                # description field
                if (type == "description" and peerType == ""):
                    peerType = getPeerType(child.text)

            if (childName == "AdditionalData"):
                meaning = child.attrib.get('meaning')

                if (meaning == "username"):
                    username = child.text

                if (meaning == "password"):
                    password = child.text

                if (meaning == "login"):
                    loginStatus = child.text

                if (meaning == "version"):
                    version = child.text

                if (meaning == "starttime"):
                    if (child.text) is not None:
                        starttime = urllib.parse.unquote(child.text)

                if (meaning == "endtime"):
                    if (child.text) is not None:
                        endtime = urllib.parse.unquote(child.text)

                if (meaning == "cve_id"):
                    vulnid = urllib.parse.unquote(child.text)

                if (meaning == "input"):
                    if (child.text) is not None:
                        url = urllib.parse.unquote(child.text).replace('\n', '; ')[2:]

            if (childName == "Analyzer"):
                analyzerID = child.attrib.get('id')

        url = fixUrl(destinationPort, url, peerType)

        #
        # persist CVE
        #
        if (len(str(vulnid)) > 2):
            elastic.putVuln(vulnid, elasticHost, esindex, createTime, source, debug)

        #
        # store attack itself
        #
        correction = elastic.putAlarm(vulnid, elasticHost, esindex, source, destination, createTime, tenant, url,
                                      analyzerID, peerType, username, password, loginStatus, version, starttime,
                                      endtime, sourcePort, destinationPort, debug)
        counter = counter + 1 - correction

        #
        # slack wanted
        #
        if ("yes" in slackuse):
            if len(str(slacktoken)) > 10:
                if len(str(vulnid)) > 4:
                    if (elastic.cveExisting(vulnid, elasticHost, esindex)):
                        communication.sendSlack("cve", slacktoken, "CVE (" + vulnid + ") found.")

    print ("Info: Added " + str(counter) + " entries")
    return True
