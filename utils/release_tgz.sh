#!/bin/sh

# Super hacky release script

# ----- SET THE VERSION NUMBER -----
CURRENTVERS=$(perl -n -e'/v(\d+).(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3\.$4"' version.go)

echo "Current version is: " $CURRENTVERS

echo -n "Major version [ENTER]: "
read maj 
echo -n "Minor version [ENTER]: "
read min 
echo -n "Patch version [ENTER]: "
read patch 
echo -n "Release version [ENTER]: "
read rel 

NEWVERSION="v$maj.$min.$patch.$rel"
NEWVERSION_DHMAKE="$maj.$min.$patch.$rel"
echo "Setting new version in source: " $NEWVERSION

perl -pi -e 's/var VERSION string = \"(.*)\"/var VERSION string = \"'$NEWVERSION'\"/g' version.go

# ----- END VERSION SETTING -----

# Clear build folder:
echo "Clearing build folder..."
rm -rf /home/tyk/tyk/build/*

VERSION=$NEWVERSION_DHMAKE
SOURCEBIN=tyk
SOURCEBINPATH=~/tyk
i386BINDIR=$SOURCEBINPATH/build/i386/tyk.linux.i386-$VERSION
amd64BINDIR=$SOURCEBINPATH/build/amd64/tyk.linux.amd64-$VERSION
armBINDIR=$SOURCEBINPATH/build/arm/tyk.linux.arm-$VERSION

i386TGZDIR=$SOURCEBINPATH/build/i386/tgz/tyk.linux.i386-$VERSION
amd64TGZDIR=$SOURCEBINPATH/build/amd64/tgz/tyk.linux.amd64-$VERSION
armTGZDIR=$SOURCEBINPATH/build/arm/tgz/tyk.linux.arm-$VERSION

cd $SOURCEBINPATH

echo "Creating TGZ dirs"
mkdir -p $i386TGZDIR
mkdir -p $amd64TGZDIR
mkdir -p $armTGZDIR


echo "Building binaries"
gox -osarch="linux/arm linux/amd64 linux/386"

rc=$?
if [[ $rc != 0 ]] ; then
    echo "Something went wrong with the build, please fix and retry"
    rm -rf rm -rf /home/tyk/tyk/build/*
    exit $rc
fi

echo "Preping TGZ Dirs"
mkdir $i386TGZDIR/apps
mkdir $i386TGZDIR/js
mkdir $i386TGZDIR/middleware
mkdir $i386TGZDIR/event_handlers
mkdir $i386TGZDIR/event_handlers/sample
mkdir $i386TGZDIR/templates
mkdir $i386TGZDIR/policies
mkdir $i386TGZDIR/install

cp $SOURCEBINPATH/apps/app_sample.json $i386TGZDIR/apps
cp $SOURCEBINPATH/templates/*.json $i386TGZDIR/templates
cp -R $SOURCEBINPATH/install/* $i386TGZDIR/install
cp $SOURCEBINPATH/middleware/*.js $i386TGZDIR/middleware
cp $SOURCEBINPATH/event_handlers/sample/*.js $i386TGZDIR/event_handlers/sample
cp $SOURCEBINPATH/js/*.js $i386TGZDIR/js
cp $SOURCEBINPATH/policies/*.json $i386TGZDIR/policies
cp $SOURCEBINPATH/tyk.conf.example $i386TGZDIR/
cp $SOURCEBINPATH/tyk.conf.example $i386TGZDIR/tyk.conf

cp -R $i386TGZDIR/* $amd64TGZDIR
cp -R $i386TGZDIR/* $armTGZDIR

cp tyk_linux_386 $i386TGZDIR/$SOURCEBIN
cp tyk_linux_amd64 $amd64TGZDIR/$SOURCEBIN
cp tyk_linux_arm $armTGZDIR/$SOURCEBIN

echo "Compressing"
cd $i386TGZDIR/../
tar -pczf $i386TGZDIR/../tyk-linux-i386-$VERSION.tar.gz tyk.linux.i386-$VERSION/

cd $amd64TGZDIR/../
tar -pczf $amd64TGZDIR/../tyk-linux-amd64-$VERSION.tar.gz tyk.linux.amd64-$VERSION/

cd $armTGZDIR/../
tar -pczf $armTGZDIR/../tyk-linux-arm-$VERSION.tar.gz tyk.linux.arm-$VERSION/

echo "Creating Deb Package for AMD64"
cd $amd64TGZDIR/
fpm -n tyk-gateway -v $VERSION  --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a amd64 -s dir -t deb ./=/opt/tyk-gateway
fpm -n tyk-gateway -v $VERSION  --rpm-sign  --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a amd64 -s dir -t rpm ./=/opt/tyk-gateway

package_cloud push tyk/tyk-gateway/ubuntu/precise *.deb
package_cloud push tyk/tyk-gateway/ubuntu/trusty *.deb
package_cloud push tyk/tyk-gateway/debian/jessie *.deb
package_cloud push tyk/tyk-gateway/el/6 *.rpm
package_cloud push tyk/tyk-gateway/el/7 *.rpm


# echo "Creating Deb Package for i386"
cd $i386TGZDIR/
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a i386 -s dir -t deb ./=/opt/tyk-gateway
fpm -n tyk-gateway -v $VERSION --rpm-sign --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a i386 -s dir -t rpm ./=/opt/tyk-gateway

package_cloud push tyk/tyk-gateway/ubuntu/precise *.deb
package_cloud push tyk/tyk-gateway/ubuntu/trusty *.deb
package_cloud push tyk/tyk-gateway/debian/jessie *.deb
package_cloud push tyk/tyk-gateway/el/6 *.rpm
package_cloud push tyk/tyk-gateway/el/7 *.rpm

echo "Creating Deb Package for ARM"
cd $armTGZDIR/
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a arm -s dir -t deb ./=/opt/tyk-gateway
fpm -n tyk-gateway -v $VERSION --rpm-sign --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a arm -s dir -t rpm ./=/opt/tyk-gateway

package_cloud push tyk/tyk-gateway/ubuntu/precise *.deb
package_cloud push tyk/tyk-gateway/ubuntu/trusty *.deb
package_cloud push tyk/tyk-gateway/debian/jessie *.deb
package_cloud push tyk/tyk-gateway/el/6 *.rpm
package_cloud push tyk/tyk-gateway/el/7 *.rpm

#echo "Re-installing"
#cd $amd64TGZDIR/
#sudo dpkg -i tyk-gateway_1.9.0.0_amd64.deb