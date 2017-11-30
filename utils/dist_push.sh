#!/bin/bash
: ${ORGDIR:="/src/github.com/TykTechnologies"}
: ${SOURCEBINPATH:="${ORGDIR}/tyk"}

echo "Set version number"
: ${VERSION:=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "$1\.$2\.$3"' version.go)}

RELEASE_DIR="$SOURCEBINPATH/build"
export PACKAGECLOUDREPO=$PC_TARGET

cd $RELEASE_DIR/

for arch in i386 amd64 arm64
do
    debName="tyk-gateway_${VERSION}_${arch}.deb"
    rpmName="tyk-gateway-$VERSION-1.${arch/amd64/x86_64}.rpm"

    echo "Pushing $debName to PackageCloud"
    package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/precise $debName
    package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/trusty $debName
    package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/xenial $debName
    package_cloud push tyk/$PACKAGECLOUDREPO/debian/jessie $debName

    echo "Pushing $rpmName to PackageCloud"
    package_cloud push tyk/$PACKAGECLOUDREPO/el/6 $rpmName
    package_cloud push tyk/$PACKAGECLOUDREPO/el/7 $rpmName
done
