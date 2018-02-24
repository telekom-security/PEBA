#!/usr/bin/env bash

pebahost="127.0.0.1"
pebaport="9922"

while true
    do
        currenttime=$(date "+%Y-%m-%d %H:%M:%S")
        echo "sending request " $currenttime

        request="""
        <EWS-SimpleMessage version=\"2.0\">
            <Authentication>
                <username>community-01-user</username>
                <token>foth{a5maiCee8fineu7</token>
            </Authentication>

              <Alert>
                <Analyzer id=\"honeytrap\"/>
                <CreateTime tz=\"+0200\">$currenttime</CreateTime>
                <Source category=\"ipv4\" port=\"200\" protocol=\"tcp\">192.168.8.1</Source>
                <Target category=\"ipv4\" port=\"80\" protocol=\"tcp\">1.2.3.4</Target>
                <Request type=\"url\">/cgi-bin/.br/style.css3/444</Request>
                <Request type=\"raw\">R0VUIC9jZ2ktYmluLy5ici9zdHlsZS5jc3MgSFRUUC8xLjENCkFjY2VwdDogdGV4dC9jc3MsKi8q
                    O3E9MC4xLCovKg0KQWNjZXB0LUVuY29kaW5nOiBnemlwLGRlZmxhdGUNCkNvbm5lY3Rpb246IEtl
                    ZXAtYWxpdmUNCkZyb206IGdvb2dsZWJvdChhdClnb29nbGVib3QuY29tDQpIb3N0OiB3d3cud2Vi
                    bWFpbGhvdXNlLmRlDQpSZWZlcmVyOiBodHRwOi8vd3d3LndlYm1haWxob3VzZS5kZS9jZ2ktYmlu
                    Ly5ici9wYXRoLnBocA0KVXNlci1BZ2VudDogTW96aWxsYS81LjAgKGNvbXBhdGlibGU7IEdvb2ds
                    ZWJvdC8yLjE7ICtodHRwOi8vd3d3Lmdvb2dsZS5jb20vYm90Lmh0bWwp
                </Request>
                <Request type=\"description\">honeytrap</Request>
                <AdditionalData meaning=\"host\" type=\"string\">www.webe.de</AdditionalData>
                  <AdditionalData meaning=\"cve_id\" type=\"string\">CVE2020-001</AdditionalData>

                <AdditionalData meaning=\"sqliteid\" type=\"integer\">3688</AdditionalData>
            </Alert>

        </EWS-SimpleMessage>

        """

        #echo $request

        curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d """$request"""  http://$pebahost:$pebaport/ews-0.1/alert/postSimpleMessage
        echo ""
        sleep 1
done

