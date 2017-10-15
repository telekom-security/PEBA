#!/usr/bin/env bash


curl --header "Content-Type:text/xml;charset=UTF-8" -d @./alarm.xml http://127.0.0.1:9922/alert/retrieveAlertsJson

