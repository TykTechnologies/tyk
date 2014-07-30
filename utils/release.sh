#!/bin/sh

# Super hacky release script

VERSION=$1
SOURCEBIN=tyk
SOURCEBINPATH=~/code/go/src/github.com/lonelycode/tyk
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
mkdir $i386TGZDIR/templates
cp $SOURCEBINPATH/apps/app_sample.json $i386TGZDIR/apps
cp $SOURCEBINPATH/templates/error.json $i386TGZDIR/templates
cp $SOURCEBINPATH/tyk.conf $i386TGZDIR

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

echo "Moving binaries"
mv tyk_linux_386 $i386BINDIR/$SOURCEBIN
mv tyk_linux_amd64 $amd64BINDIR/$SOURCEBIN
mv tyk_linux_arm $armBINDIR/$SOURCEBIN

echo "Copying configuration files into distros"
cp $SOURCEBINPATH/apps/app_sample.json $i386BINDIR
cp $SOURCEBINPATH/templates/error.json $i386BINDIR
cp $SOURCEBINPATH/tyk.conf $i386BINDIR

cp $SOURCEBINPATH/apps/app_sample.json $amd64BINDIR
cp $SOURCEBINPATH/templates/error.json $amd64BINDIR
cp $SOURCEBINPATH/tyk.conf $amd64BINDIR

cp $SOURCEBINPATH/apps/app_sample.json $armBINDIR
cp $SOURCEBINPATH/templates/error.json $armBINDIR
cp $SOURCEBINPATH/tyk.conf $armBINDIR

# -------------------------------------------------------
echo "Preparing i386"
cd $i386BINDIR

# Create the packaging skeleton (debian/*)
#dh_make -s --indep --createorig --yes
dh_make --s --createorig --yes

# Remove make calls
grep -v makefile debian/rules > debian/rules.new
mv debian/rules.new debian/rules

# debian/install must contain the list of scripts to install
# as well as the target directory
echo $SOURCEBIN usr/bin > debian/install
echo "app_sample.json" etc/tyk/apps >> debian/install
echo "error.json" etc/tyk/templates >> debian/install
echo "tyk.conf" etc/tyk >> debian/install

sed -i 's/.*Maintainer: Martin Buhr <martin@unknown>.*/Maintainer: Martin Buhr <martin@jive.ly>/' debian/control
sed -i 's/.*Homepage: <insert the upstream URL, if relevant>.*/Homepage: http://tyk.io/' debian/control
sed -i 's/.*Description: <insert up to 60 chars description>.*/Description: A lightweight API gateway server/' debian/control
sed -i 's/.* <insert long description, indented with spaces>.*/ A lightweight API gateway server written in Go/' debian/control

# We don't want a quilt based package
echo "1.0" > debian/source/format
# Remove the example files
rm debian/*.ex

# Build the package.
# You  will get a lot of warnings.
debuild -us -uc

# -------------------------------------------------------
echo "Preparing amd64"
cd $amd64BINDIR

# Create the packaging skeleton (debian/*)
dh_make -s --indep --createorig --yes

# Remove make calls
grep -v makefile debian/rules > debian/rules.new
mv debian/rules.new debian/rules

# debian/install must contain the list of scripts to install
# as well as the target directory
echo $SOURCEBIN usr/bin > debian/install
echo "app_sample.json" etc/tyk/apps >> debian/install
echo "error.json" etc/tyk/templates >> debian/install
echo "tyk.conf" etc/tyk >> debian/install

sed -i 's/.*Maintainer: Martin Buhr <martin@unknown>.*/Maintainer: Martin Buhr <martin@jive.ly>/' debian/control
sed -i 's/.*Homepage: <insert the upstream URL, if relevant>.*/Homepage: http://tyk.io/' debian/control
sed -i 's/.*Description: <insert up to 60 chars description>.*/Description: A lightweight API gateway server/' debian/control
sed -i 's/.* <insert long description, indented with spaces>.*/ A lightweight API gateway server written in Go/' debian/control


# We don't want a quilt based package
echo "1.0" > debian/source/format

# Remove the example files
rm debian/*.ex

# Build the package.
# You  will get a lot of warnings.
debuild -us -uc

# -------------------------------------------------------
echo "Preparing arm"
cd $armBINDIR

# Create the packaging skeleton (debian/*)
dh_make -s --indep --createorig --yes

# Remove make calls
grep -v makefile debian/rules > debian/rules.new
mv debian/rules.new debian/rules

# debian/install must contain the list of scripts to install
# as well as the target directory
echo $SOURCEBIN usr/bin > debian/install
echo "app_sample.json" etc/tyk/apps >> debian/install
echo "error.json" etc/tyk/templates >> debian/install
echo "tyk.conf" etc/tyk >> debian/install

sed -i 's/.*Maintainer: Martin Buhr <martin@unknown>.*/Maintainer: Martin Buhr <martin@jive.ly>/' debian/control
sed -i 's/.*Homepage: <insert the upstream URL, if relevant>.*/Homepage: http://tyk.io/' debian/control
sed -i 's/.*Description: <insert up to 60 chars description>.*/Description: A lightweight API gateway server/' debian/control
sed -i 's/.* <insert long description, indented with spaces>.*/ A lightweight API gateway server written in Go/' debian/control


# We don't want a quilt based package
echo "1.0" > debian/source/format

# Remove the example files
rm debian/*.ex

# Build the package.
# You  will get a lot of warnings.
debuild -us -uc


