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
gox -os="linux"

rc=$?
if [[ $rc != 0 ]] ; then
    echo "Something went wrong with the build, please fix and retry"
    rm -rf build
    exit $rc
fi

echo "Preping TGZ Dirs"
mkdir $i386TGZDIR/apps
mkdir $i386TGZDIR/js
mkdir $i386TGZDIR/middleware
mkdir $i386TGZDIR/middleware/python
mkdir $i386TGZDIR/middleware/lua
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
cp -R $SOURCEBINPATH/coprocess $i386TGZDIR/

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

cd $SOURCEBINPATH

# echo "Moving binaries"
# mv tyk_linux_386 $i386BINDIR/$SOURCEBIN
# mv tyk_linux_amd64 $amd64BINDIR/$SOURCEBIN
# mv tyk_linux_arm $armBINDIR/$SOURCEBIN

# echo "Copying configuration files into distros"
# cp $SOURCEBINPATH/apps/app_sample.json $i386BINDIR
# cp $SOURCEBINPATH/templates/*.json $i386BINDIR
# cp $SOURCEBINPATH/tyk.conf.example $i386BINDIR/tyk.conf
# cp -r $SOURCEBINPATH/middleware/*.js $i386BINDIR
# cp -r $SOURCEBINPATH/event_handlers/sample/*.js $i386BINDIR
# cp -r $SOURCEBINPATH/js/tyk.js $i386BINDIR
# cp -r $SOURCEBINPATH/policies/policies.json $i386BINDIR


# cp $SOURCEBINPATH/apps/app_sample.json $amd64BINDIR
# cp $SOURCEBINPATH/templates/*.json $amd64BINDIR
# cp $SOURCEBINPATH/tyk.conf.example $amd64BINDIR/tyk.conf
# cp -r $SOURCEBINPATH/middleware/*.js $amd64BINDIR
# cp -r $SOURCEBINPATH/event_handlers/sample/*.js $amd64BINDIR
# cp -r $SOURCEBINPATH/js/tyk.js $amd64BINDIR
# cp -r $SOURCEBINPATH/policies/policies.json $amd64BINDIR


# cp $SOURCEBINPATH/apps/app_sample.json $armBINDIR
# cp $SOURCEBINPATH/templates/*.json $armBINDIR
# cp $SOURCEBINPATH/tyk.conf.example $armBINDIR/tyk.conf
# cp -r $SOURCEBINPATH/middleware/*.js $armBINDIR
# cp -r $SOURCEBINPATH/event_handlers/sample/*.js $armBINDIR
# cp -r $SOURCEBINPATH/js/tyk.js $armBINDIR
# cp -r $SOURCEBINPATH/policies/policies.json $armBINDIR

# # -------------------------------------------------------
# echo "Preparing i386"
# cd $i386BINDIR

# # Create the packaging skeleton (debian/*)
# #dh_make -s --indep --createorig --yes
# dh_make -s --indep --createorig --yes

# # Remove make calls
# grep -v makefile debian/rules > debian/rules.new
# mv debian/rules.new debian/rules

# # debian/install must contain the list of scripts to install
# # as well as the target directory
# echo $SOURCEBIN usr/bin > debian/install
# echo "app_sample.json" etc/tyk/apps >> debian/install
# echo "error.json" etc/tyk/templates >> debian/install
# echo "default_webhook.json" etc/tyk/templates >> debian/install
# echo "tyk.conf" etc/tyk >> debian/install
# echo "tyk.js" etc/tyk/js >> debian/install
# echo "policies.json" etc/tyk/policies >> debian/install
# echo "sampleMiddleware.js" etc/tyk/middleware/sample >> debian/install
# echo "firebase_test.js" etc/tyk/event_handlers/sample >> debian/install
# echo "sample_event_handler.js" etc/tyk/event_handlers/sample >> debian/install
# echo "session_editor.js" etc/tyk/event_handlers/sample >> debian/install

# sed -i 's/.*Maintainer: Martin Buhr <martin@jive.ly>.*/Maintainer: Martin Buhr <martin@jive.ly>/' debian/control
# sed -i 's/.*Homepage: http://tyk.io/.*/Homepage: http://tyk.io/' debian/control
# sed -i 's/.*Description:A lightweight API gateway server.*/Description: A lightweight API gateway server/' debian/control
# sed -i 's/.*A lightweight API gateway server written in Go.*/ A lightweight API gateway server written in Go/' debian/control

# # We don't want a quilt based package
# echo "1.0" > debian/source/format
# # Remove the example files
# rm debian/*.ex

# # Build the package.
# # You  will get a lot of warnings.
# debuild -us -uc

# # -------------------------------------------------------
# echo "Preparing amd64"
# cd $amd64BINDIR

# # Create the packaging skeleton (debian/*)
# dh_make -s --indep --createorig --yes

# # Remove make calls
# grep -v makefile debian/rules > debian/rules.new
# mv debian/rules.new debian/rules

# # debian/install must contain the list of scripts to install
# # as well as the target directory
# echo $SOURCEBIN usr/bin > debian/install
# echo "app_sample.json" etc/tyk/apps >> debian/install
# echo "error.json" etc/tyk/templates >> debian/install
# echo "default_webhook.json" etc/tyk/templates >> debian/install
# echo "tyk.conf" etc/tyk >> debian/install
# echo "tyk.js" etc/tyk/js >> debian/install
# echo "policies.json" etc/tyk/policies >> debian/install
# echo "sampleMiddleware.js" etc/tyk/middleware/sample >> debian/install
# echo "firebase_test.js" etc/tyk/event_handlers/sample >> debian/install
# echo "sample_event_handler.js" etc/tyk/event_handlers/sample >> debian/install
# echo "session_editor.js" etc/tyk/event_handlers/sample >> debian/install

# sed -i 's/.*Maintainer: Martin Buhr <martin@jive.ly>.*/Maintainer: Martin Buhr <martin@jive.ly>/' debian/control
# sed -i 's/.*Homepage: http://tyk.io/.*/Homepage: http://tyk.io/' debian/control
# sed -i 's/.*Description:A lightweight API gateway server.*/Description: A lightweight API gateway server/' debian/control
# sed -i 's/.*A lightweight API gateway server written in Go.*/ A lightweight API gateway server written in Go/' debian/control


# # We don't want a quilt based package
# echo "1.0" > debian/source/format

# # Remove the example files
# rm debian/*.ex

# # Build the package.
# # You  will get a lot of warnings.
# debuild -us -uc

# # -------------------------------------------------------
# echo "Preparing arm"
# cd $armBINDIR

# # Create the packaging skeleton (debian/*)
# dh_make -s --indep --createorig --yes

# # Remove make calls
# grep -v makefile debian/rules > debian/rules.new
# mv debian/rules.new debian/rules

# # debian/install must contain the list of scripts to install
# # as well as the target directory
# echo $SOURCEBIN usr/bin > debian/install
# echo "app_sample.json" etc/tyk/apps >> debian/install
# echo "error.json" etc/tyk/templates >> debian/install
# echo "default_webhook.json" etc/tyk/templates >> debian/install
# echo "tyk.conf" etc/tyk >> debian/install
# echo "tyk.js" etc/tyk/js >> debian/install
# echo "policies.json" etc/tyk/policies >> debian/install
# echo "sampleMiddleware.js" etc/tyk/middleware/sample >> debian/install
# echo "firebase_test.js" etc/tyk/event_handlers/sample >> debian/install
# echo "sample_event_handler.js" etc/tyk/event_handlers/sample >> debian/install
# echo "session_editor.js" etc/tyk/event_handlers/sample >> debian/install

# sed -i 's/.*Maintainer: Martin Buhr <martin@jive.ly>.*/Maintainer: Martin Buhr <martin@jive.ly>/' debian/control
# sed -i 's/.*Homepage: http://tyk.io/.*/Homepage: http://tyk.io/' debian/control
# sed -i 's/.*Description:A lightweight API gateway server.*/Description: A lightweight API gateway server/' debian/control
# sed -i 's/.*A lightweight API gateway server written in Go.*/ A lightweight API gateway server written in Go/' debian/control


# # We don't want a quilt based package
# echo "1.0" > debian/source/format

# # Remove the example files
# rm debian/*.ex

# # Build the package.
# # You  will get a lot of warnings.
# debuild -us -uc


