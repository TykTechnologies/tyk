#!/bin/sh
CURRENTVERS=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"' version.go)

echo "Current version is: " $CURRENTVERS

echo -n "Major version [ENTER]: "
read maj 
echo -n "Minor version [ENTER]: "
read min 
echo -n "Patch version [ENTER]: "
read patch 

NEWVERSION="v$maj.$min.$patch"
echo "Setting new version in source: " $NEWVERSION

perl -pi -e 's/var VERSION = \"(.*)\"/var VERSION = \"'$NEWVERSION'\"/g' version.go
