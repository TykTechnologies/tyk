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

# Add error handling for specific error conditions
if [ -z "$maj" ] || [ -z "$min" ] || [ -z "$patch" ]; then
    echo "Error: Invalid version entered"
    exit 1
fi

perl -pi -e 's/var VERSION = \"(.*)\"/var VERSION = \"'$NEWVERSION'\"/g' version.go
# Add logging for failure
if [ $? -ne 0 ]; then
    echo "Error: Failed to set new version in source"
    exit 1
fi
