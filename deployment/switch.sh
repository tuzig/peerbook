#!/usr/bin/env bash
# a script to switch between the targets of /opt/peerbook/next and /opt/peerbook/live
t1=$(readlink /opt/peerbook/next)
t2=$(readlink /opt/peerbook/live)
ln -sfn $t2 /opt/peerbook/next
ln -sfn $t1 /opt/peerbook/live
service nginx reload
