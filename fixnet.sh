#!/bin/sh

if [ -z "$1" ]
  then
    echo "Usage: fixnet.sh [ssh alias]"
fi

ssh $1 "rm /Library/Preferences/com.apple.networkextension*.plist; killall CommCenter"