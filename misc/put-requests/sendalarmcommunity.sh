#!/usr/bin/env bash

curl -L -X POST --header "Content-Type:text/xml;charset=UTF-8" -d @./alarmht.xml https://community.sicherheitstacho.eu/ews-0.1/alert/postSimpleMessage --verbose
