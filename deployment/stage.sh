#!/usr/bin/env bash

service="pb-$(readlink /opt/peerbook/next)"
supervisorctl stop $service
aws s3 cp s3://peerbook-staging/peerbook /opt/peerbook/next 
chmod +x /opt/peerbook/next/peerbook
supervisorctl start $service
