#!/bin/sh
set -e

# Super hacky release script

# ----- SET THE VERSION NUMBER -----
CURRENTVERS=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"' version.go)

echo "Current version is: " $CURRENTVERS 
DATE=$(date +'%m-%d-%Y')
BUILDVERS="$CURRENTVERS-nightly-$DATE" 
echo "Build will be: " $BUILDVERS

NEWVERSION=$BUILDVERS
NEWVERSION_DHMAKE=$BUILDVERS
echo "Setting new version in source: " $NEWVERSION

perl -pi -e 's/var VERSION string = \"(.*)\"/var VERSION string = \"'$NEWVERSION'\"/g' version.go

# ----- END VERSION SETTING -----

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

echo "Getting deps"
go get -t -d -v ./...

echo "Fixing MGO Version"
cd $GOPATH/src/gopkg.in/mgo.v2/
git checkout tags/r2016.02.04
cd $SOURCEBINPATH

echo "Installing cross-compiler"
go get github.com/mitchellh/gox

echo "Creating build directory"
rm -rf build
mkdir -p $i386BINDIR
mkdir -p $amd64BINDIR
mkdir -p $armBINDIR

echo "Creating TGZ dirs"
mkdir -p $i386TGZDIR
mkdir -p $amd64TGZDIR
mkdir -p $armTGZDIR


echo "Building binaries"
gox -osarch="linux/amd64" 
gox -osarch="linux/386"
gox -osarch="linux/arm"

echo "Preping TGZ Dirs"
mkdir $i386TGZDIR/apps
mkdir $i386TGZDIR/js
mkdir $i386TGZDIR/middleware
mkdir $i386TGZDIR/event_handlers
mkdir $i386TGZDIR/event_handlers/sample
mkdir $i386TGZDIR/templates
mkdir $i386TGZDIR/policies

cp $SOURCEBINPATH/apps/app_sample.json $i386TGZDIR/apps
cp $SOURCEBINPATH/templates/*.json $i386TGZDIR/templates
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

echo "TGZ Created"

echo "Creating release directory and copying files"
cd $SOURCEBINPATH
RELEASEPATH=$SOURCEBINPATH/build/release
mkdir $RELEASEPATH
cp $i386TGZDIR/../*.tar.gz $RELEASEPATH
cp $amd64TGZDIR/../*.tar.gz $RELEASEPATH
cp $armTGZDIR/../*.tar.gz $RELEASEPATH
cp utils/nightlies/index.html $RELEASEPATH
echo "Done"

