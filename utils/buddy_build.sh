#!/bin/bash
echo Set version number
export VERSION=$(perl -n -e'/v(\d+).(\d+).(\d+).(\d+)/'' && print "$1\.$2\.$3\.$4"' version.go)

echo Generating key
[[ $(gpg --list-keys | grep -w 729EA673) ]] && echo "Key exists" || gpg --import build_key.key

echo Prepare the release directories
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

orgDir=/src/github.com/TykTechnologies
cliDIR=/src/github.com/TykTechnologies/tyk-cli
cliTmpDir=$SOURCEBINPATH/temp/cli

echo "Clearing CLI temp folder"
rm -rf $cliTmpDir
mkdir -p $cliTmpDir

echo "Preparing CLI Build"
cd $orgDir
git clone https://github.com/TykTechnologies/tyk-cli.git
cd $cliDIR
git checkout master
go get -v ./...
gox -osarch="linux/arm64 linux/amd64 linux/386"

echo "Copying CLI Build files"
cp tyk-cli_linux_386 $cliTmpDir/
cp tyk-cli_linux_amd64 $cliTmpDir/
cp tyk-cli_linux_arm64 $cliTmpDir/

echo "Cleaning up"
rm tyk-cli_linux_386
rm tyk-cli_linux_amd64
rm tyk-cli_linux_arm64

echo "Retuning to Tyk build"
cd $SOURCEBINPATH

echo Starting Tyk build
cd $SOURCEBINPATH

echo Blitzing TGZ dirs
rm -rf $i386TGZDIR
rm -rf $amd64TGZDIR
rm -rf $armTGZDIR

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

echo Prepping TGZ Dirs
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

cp $cliTmpDir/tyk-cli_linux_386 $i386TGZDIR/utils/$CLIBIN
cp $cliTmpDir/tyk-cli_linux_amd64 $amd64TGZDIR/utils/$CLIBIN
cp $cliTmpDir/tyk-cli_linux_arm64 $armTGZDIR/utils/$CLIBIN

echo Compressing
cd $i386TGZDIR/../
tar -pczf $i386TGZDIR/../tyk-linux-i386-$VERSION.tar.gz tyk.linux.i386-$VERSION/

cd $amd64TGZDIR/../
tar -pczf $amd64TGZDIR/../tyk-linux-amd64-$VERSION.tar.gz tyk.linux.amd64-$VERSION/

cd $armTGZDIR/../
tar -pczf $armTGZDIR/../tyk-linux-arm64-$VERSION.tar.gz tyk.linux.arm64-$VERSION/

echo "Removing old builds"
rm -f *.deb
rm -f *.rpm

echo Creating Deb Package for AMD64
cd $amd64TGZDIR/
fpm -n tyk-gateway -v $VERSION  --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a amd64 -s dir -t deb ./=/opt/tyk-gateway
fpm -n tyk-gateway -v $VERSION  --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a amd64 -s dir -t rpm ./=/opt/tyk-gateway

AMDDEBNAME="tyk-gateway_"$VERSION"_amd64.deb"
AMDRPMNAME="tyk-gateway-"$VERSION"-1.x86_64.rpm"

echo "Signing AMD RPM"
~/build_tools/rpm-sign.exp $amd64TGZDIR/$AMDRPMNAME

echo Creating Deb Package for i386
cd $i386TGZDIR/
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a i386 -s dir -t deb ./=/opt/tyk-gateway
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a i386 -s dir -t rpm ./=/opt/tyk-gateway

i386DEBNAME="tyk-gateway_"$VERSION"_i386.deb"
i386RPMNAME="tyk-gateway-"$VERSION"-1.i386.rpm"

echo "Signing i386 RPM"
~/build_tools/rpm-sign.exp $i386TGZDIR/$i386RPMNAME

echo Creating Deb Package for ARM
cd $armTGZDIR/
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a arm64 -s dir -t deb ./=/opt/tyk-gateway
fpm -n tyk-gateway -v $VERSION --after-install $amd64TGZDIR/install/post_install.sh --after-remove $amd64TGZDIR/install/post_remove.sh -a arm64 -s dir -t rpm ./=/opt/tyk-gateway

ARMDEBNAME="tyk-gateway_"$VERSION"_arm64.deb"
ARMRPMNAME="tyk-gateway-"$VERSION"-1.arm64.rpm"

echo "Signing Arm RPM"
~/build_tools/rpm-sign.exp $armTGZDIR/$ARMRPMNAME