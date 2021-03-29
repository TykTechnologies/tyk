#!/bin/bash
echo "Creating user and group..."
GROUPNAME="tyk"
USERNAME="tyk"
OLD_DIR="/opt/tyk-gateway"
NEW_DIR="/opt/tyk"

getent group "$GROUPNAME" >/dev/null || groupadd -r "$GROUPNAME"
getent passwd "$USERNAME" >/dev/null || useradd -r -g "$GROUPNAME" -M -s /sbin/nologin -c "Tyk service user" "$USERNAME"
if [ -d ${OLD_DIR} ]; then
    echo "Found legacy directory $OLDDIR. This will be moved to $NEW_DIR, no further action is required on your part."
    mv $OLD_DIR $NEW_DIR && ln $NEW_DIR $OLD_DIR
fi
