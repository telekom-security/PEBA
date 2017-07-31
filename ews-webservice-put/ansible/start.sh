#!/usr/bin/env bash
ansible -i ./hosts all -m ping -u root -k -v