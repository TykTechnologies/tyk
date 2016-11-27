#!/bin/bash
echo Set version number
export VERSION=$(perl -n -e'/v(\d+).(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3\.$4"' version.go)

echo Prepare the release directories
export SOURCEBIN=tyk
export SOURCEBINPATH=/src/github.com/TykTechnologies/tyk
export i386BINDIR=$SOURCEBINPATH/build/i386/tyk.linux.i386-$VERSION
export amd64BINDIR=$SOURCEBINPATH/build/amd64/tyk.linux.amd64-$VERSION
export armBINDIR=$SOURCEBINPATH/build/arm/tyk.linux.arm64-$VERSION

export i386TGZDIR=$SOURCEBINPATH/build/i386/tgz/tyk.linux.i386-$VERSION
export amd64TGZDIR=$SOURCEBINPATH/build/amd64/tgz/tyk.linux.amd64-$VERSION
export armTGZDIR=$SOURCEBINPATH/build/arm/tgz/tyk.linux.arm64-$VERSION
export PACKAGECLOUDREPO=tyk-gateway-auto

echo Starting Tyk build
cd $SOURCEBINPATH

echo Creating TGZ dirs
mkdir -p $i386TGZDIR
mkdir -p $amd64TGZDIR
mkdir -p $armTGZDIR

echo Building Tyk binaries
gox -osarch="linux/arm64 linux/amd64 linux/386" -tags 'coprocess grpc'

echo Building Tyk CP binaries
export CPBINNAME_LUA=tyk_linux_amd64_lua
export CPBINNAME_PYTHON=tyk_linux_amd64_python

gox -osarch="linux/amd64" -tags 'coprocess python' -output '{{.Dir}}_{{.OS}}_{{.Arch}}_python'
gox -osarch="linux/amd64" -tags 'coprocess lua' -output '{{.Dir}}_{{.OS}}_{{.Arch}}_lua'

echo Preping TGZ Dirs
mkdir -p $i386TGZDIR/apps
mkdir -p $i386TGZDIR/js
mkdir -p $i386TGZDIR/middleware
mkdir -p $i386TGZDIR/middleware/python
mkdir -p $i386TGZDIR/middleware/lua
mkdir -p $i386TGZDIR/event_handlers
mkdir -p $i386TGZDIR/event_handlers/sample
mkdir -p $i386TGZDIR/templates
mkdir -p $i386TGZDIR/policies
mkdir -p $i386TGZDIR/utils
mkdir -p $i386TGZDIR/install

cp $SOURCEBINPATH/apps/app_sample.json $i386TGZDIR/apps
cp $SOURCEBINPATH/templates/*.json $i386TGZDIR/templates
cp -R $SOURCEBINPATH/install/* $i386TGZDIR/install
cp $SOURCEBINPATH/middleware/*.js $i386TGZDIR/middleware
cp $SOURCEBINPATH/event_handlers/sample/*.js $i386TGZDIR/event_handlers/sample
cp $SOURCEBINPATH/js/*.js $i386TGZDIR/js
cp $SOURCEBINPATH/policies/*.json $i386TGZDIR/policies
cp $SOURCEBINPATH/tyk.conf.example $i386TGZDIR/
cp $SOURCEBINPATH/tyk.conf.example $i386TGZDIR/tyk.conf
cp -R $SOURCEBINPATH/coprocess $i386TGZDIR/

cp -R $i386TGZDIR/* $amd64TGZDIR
cp -R $i386TGZDIR/* $armTGZDIR

cp tyk_linux_386 $i386TGZDIR/$SOURCEBIN
cp tyk_linux_arm64 $armTGZDIR/$SOURCEBIN
cp tyk_linux_amd64 $amd64TGZDIR/$SOURCEBIN
cp $CPBINNAME_LUA $amd64TGZDIR/$SOURCEBIN-lua
cp $CPBINNAME_PYTHON $amd64TGZDIR/$SOURCEBIN-python

echo Compressing
cd $i386TGZDIR/../
tar -pczf $i386TGZDIR/../tyk-linux-i386-$VERSION.tar.gz tyk.linux.i386-$VERSION/

cd $amd64TGZDIR/../
tar -pczf $amd64TGZDIR/../tyk-linux-amd64-$VERSION.tar.gz tyk.linux.amd64-$VERSION/

cd $armTGZDIR/../
tar -pczf $armTGZDIR/../tyk-linux-arm64-$VERSION.tar.gz tyk.linux.arm64-$VERSION/

echo setting locales
locale-gen --purge "en_US.UTF-8"
locale-gen "en_US.UTF-8"
echo -e 'LANG="en_US.UTF-8"\nLANGUAGE="en_US:en"\n' > /etc/default/locale
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LANGUAGE=en_US.UTF-8

echo Creating Deb Package for AMD64
cd $amd64TGZDIR/
fpm -n tyk-gateway -v $VERSION  --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a amd64 -s dir -t deb ./=/opt/tyk-gateway
fpm -n tyk-gateway -v $VERSION  --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a amd64 -s dir -t rpm ./=/opt/tyk-gateway

AMDDEBNAME=tyk-gateway_$VERSION_arm64.deb
AMDRPMNAME=tyk-gateway-$VERSION-1.x86_64.rpm

package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/precise $AMDDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/trusty $AMDDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/debian/jessie $AMDDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/6 $AMDRPMNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/7 $AMDRPMNAME

echo Creating Deb Package for i386
cd $i386TGZDIR/
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a i386 -s dir -t deb ./=/opt/tyk-gateway
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a i386 -s dir -t rpm ./=/opt/tyk-gateway

i386DEBNAME=tyk-gateway_$VERSION_i386.deb
i386RPMNAME=tyk-gateway-$VERSION-1.i386.rpm

package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/precise $i386DEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/trusty $i386DEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/debian/jessie $i386DEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/6 $i386RPMNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/7 $i386RPMNAME

echo Creating Deb Package for ARM
cd $armTGZDIR/
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a arm64 -s dir -t deb ./=/opt/tyk-gateway
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a arm64 -s dir -t rpm ./=/opt/tyk-gateway

ARMDEBNAME=tyk-gateway_$VERSION_arm64.deb
ARMRPMNAME=tyk-gateway-$VERSION-1.arm64.rpm

package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/precise $ARMDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/ubuntu/trusty $ARMDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/debian/jessie $ARMDEBNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/6 $ARMRPMNAME
package_cloud push tyk/$PACKAGECLOUDREPO/el/7 $ARMRPMNAME