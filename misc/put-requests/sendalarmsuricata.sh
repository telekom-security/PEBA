#!/usr/bin/env bash

curl -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./alarmsuricata.xml http://127.0.0.1:9922/ews-0.1/alert/postSimpleMessage
