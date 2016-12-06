#!/bin/bash
export VERSION=$(perl -n -e'/v(\d+).(\d+).(\d+).(\d+)/'' && print "$1\.$2\.$3\.$4"' version.go)

export SOURCEBIN=tyk
export CLIBIN=tyk-cli
export SOURCEBINPATH=/src/github.com/TykTechnologies/tyk
export i386BINDIR=$SOURCEBINPATH/build/i386/tyk.linux.i386-$VERSION
export amd64BINDIR=$SOURCEBINPATH/build/amd64/tyk.linux.amd64-$VERSION
export armBINDIR=$SOURCEBINPATH/build/arm/tyk.linux.arm64-$VERSION

export i386TGZDIR=$SOURCEBINPATH/build/i386/tgz/tyk.linux.i386-$VERSION
export amd64TGZDIR=$SOURCEBINPATH/build/amd64/tgz/tyk.linux.amd64-$VERSION
export armTGZDIR=$SOURCEBINPATH/build/arm/tgz/tyk.linux.arm64-$VERSION
export PACKAGECLOUDREPO=$PC_TARGET

echo Pushing Deb Package for amd64
cd $amd64TGZDIR/
AMDDEBNAME="tyk-gateway_"$VERSION"_amd64.deb"
AMDRPMNAME="tyk-gateway-"$VERSION"-1.x86_64.rpm"

package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/precise $AMDDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/trusty $AMDDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/debian/jessie $AMDDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/6 $AMDRPMNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/7 $AMDRPMNAME

echo Pushing Deb Package for i386
cd $i386TGZDIR/

i386DEBNAME="tyk-gateway_"$VERSION"_i386.deb"
i386RPMNAME="tyk-gateway-"$VERSION"-1.i386.rpm"

package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/precise $i386DEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/trusty $i386DEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/debian/jessie $i386DEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/6 $i386RPMNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/7 $i386RPMNAME

echo Pushing Deb Package for ARM
cd $armTGZDIR/

ARMDEBNAME="tyk-gateway_"$VERSION"_arm64.deb"
ARMRPMNAME="tyk-gateway-"$VERSION"-1.arm64.rpm"

package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/precise $ARMDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/trusty $ARMDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/debian/jessie $ARMDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/6 $ARMRPMNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/7 $ARMRPMNAME