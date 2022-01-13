#!/bin/bash
: ${ORGDIR:="/go/src/github.com/TykTechnologies"}
: ${SOURCEBINPATH:="${ORGDIR}/tyk"}
: ${DEBVERS:="ubuntu/xenial"}
: ${RPMVERS:="el/7"}
: ${PKGNAME:="tyk-gateway"}
: ${PC_TARGET:="tyk-gateway-unstable"}

echo "Set version number"
: ${VERSION:=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "$1\.$2\.$3"' version.go)}

RELEASE_DIR="$SOURCEBINPATH/build"

cd $RELEASE_DIR/

for arch in amd64 arm64
do
    debName="${PKGNAME}_${VERSION}_${arch}.deb"
    rpmName="$PKGNAME-$VERSION-1.${arch/amd64/x86_64}.rpm"

    for ver in $DEBVERS
    do
        echo "Pushing $debName to PackageCloud $ver"
        package_cloud push tyk/$PC_TARGET/$ver $debName
    done

    for ver in $RPMVERS
    do
        echo "Pushing $rpmName to PackageCloud $ver"
        package_cloud push tyk/$PC_TARGET/$ver $rpmName
    done
done
