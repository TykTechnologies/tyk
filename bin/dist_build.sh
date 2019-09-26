#!/bin/bash
: ${ORGDIR:="/src/github.com/TykTechnologies"}
: ${SOURCEBINPATH:="${ORGDIR}/tyk"}
: ${SIGNKEY:="729EA673"}
: ${BUILDPKGS:="1"}
: ${PKGNAME:="tyk-gateway"}
BUILDTOOLSDIR=$SOURCEBINPATH/build_tools
BUILDDIR=$SOURCEBINPATH/build

echo "Set version number"
: ${VERSION:=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "$1\.$2\.$3"' version.go)}

if [ $BUILDPKGS == "1" ]; then
    echo "Importing signing key"
    gpg --list-keys | grep -w $SIGNKEY && echo "Key exists" || gpg --batch --import $BUILDTOOLSDIR/build_key.key
fi

echo "Prepare the release directories"

export SOURCEBIN=tyk
export CLIBIN=tyk-cli

declare -A ARCHTGZDIRS
ARCHTGZDIRS=(
    [i386]=$BUILDDIR/i386/tgz/tyk.linux.i386-$VERSION
    [amd64]=$BUILDDIR/amd64/tgz/tyk.linux.amd64-$VERSION
    [arm64]=$BUILDDIR/arm/tgz/tyk.linux.arm64-$VERSION
)

cliDIR=$ORGDIR/tyk-cli
cliTmpDir=$SOURCEBINPATH/temp/cli
DESCRIPTION="Tyk Open Source API Gateway written in Go"

echo "Clearing CLI temp folder"
rm -rf $cliTmpDir
mkdir -p $cliTmpDir

echo "Preparing CLI Build"
cd $ORGDIR
[ -d $cliDIR ] || git clone https://github.com/TykTechnologies/tyk-cli.git
cd $cliDIR
git checkout master
git pull
go get -v ./...
gox -osarch="linux/arm64 linux/amd64 linux/386"

echo "Copying CLI Build files"
mv tyk-cli_linux_* $cliTmpDir/

echo "Starting Tyk build"
cd $SOURCEBINPATH

echo "Blitzing TGZ dirs"
for arch in ${!ARCHTGZDIRS[@]}
do
    rm -rf ${ARCHTGZDIRS[$arch]}
    mkdir -p ${ARCHTGZDIRS[$arch]}
done

echo "Building Tyk binaries"
gox -osarch="linux/amd64 linux/386" -cgo
# Build arm64 without CGO (no Python plugins), an improved cross-compilation toolkit is needed for that
gox -osarch="linux/arm64"

TEMPLATEDIR=${ARCHTGZDIRS[i386]}
echo "Prepping TGZ Dirs"
mkdir -p $TEMPLATEDIR/apps
mkdir -p $TEMPLATEDIR/js
mkdir -p $TEMPLATEDIR/middleware
mkdir -p $TEMPLATEDIR/middleware/python
mkdir -p $TEMPLATEDIR/middleware/lua
mkdir -p $TEMPLATEDIR/event_handlers
mkdir -p $TEMPLATEDIR/event_handlers/sample
mkdir -p $TEMPLATEDIR/templates
mkdir -p $TEMPLATEDIR/policies
mkdir -p $TEMPLATEDIR/utils
mkdir -p $TEMPLATEDIR/install

cp $SOURCEBINPATH/apps/app_sample.json $TEMPLATEDIR/apps
cp $SOURCEBINPATH/templates/*.json $TEMPLATEDIR/templates
cp -R $SOURCEBINPATH/install/* $TEMPLATEDIR/install
cp $SOURCEBINPATH/middleware/*.js $TEMPLATEDIR/middleware
cp $SOURCEBINPATH/event_handlers/sample/*.js $TEMPLATEDIR/event_handlers/sample
cp $SOURCEBINPATH/policies/*.json $TEMPLATEDIR/policies
cp $SOURCEBINPATH/tyk.conf.example $TEMPLATEDIR/
cp $SOURCEBINPATH/tyk.conf.example $TEMPLATEDIR/tyk.conf
cp -R $SOURCEBINPATH/coprocess $TEMPLATEDIR/

# Clone template dir to all architectures and copy corresponding binaries
for arch in ${!ARCHTGZDIRS[@]}
do
    archDir=${ARCHTGZDIRS[$arch]}
    [ $archDir != $TEMPLATEDIR ] && cp -R $TEMPLATEDIR/* $archDir
    mv tyk_linux_${arch/i386/386} $archDir/$SOURCEBIN
    cp $cliTmpDir/tyk-cli_linux_${arch/i386/386} $archDir/utils/$CLIBIN
done

echo "Compressing"
for arch in ${!ARCHTGZDIRS[@]}
do
    cd ${ARCHTGZDIRS[$arch]}/../
    tar -pczf ${ARCHTGZDIRS[$arch]}/../tyk-linux-$arch-$VERSION.tar.gz tyk.linux.$arch-$VERSION/
done

# Nothing more to do if we're not going to build packages
[ $BUILDPKGS != "1" ] && exit 0

CONFIGFILES=(
    --config-files /opt/tyk-gateway/apps
    --config-files /opt/tyk-gateway/templates
    --config-files /opt/tyk-gateway/middleware
    --config-files /opt/tyk-gateway/event_handlers
    --config-files /opt/tyk-gateway/js
    --config-files /opt/tyk-gateway/policies
    --config-files /opt/tyk-gateway/tyk.conf
)
FPMCOMMON=(
    --name "$PKGNAME"
    --description "$DESCRIPTION"
    -v $VERSION
    --vendor "Tyk Technologies Ltd"
    -m "<info@tyk.io>"
    --url "https://tyk.io"
    -s dir
    --before-install $TEMPLATEDIR/install/before_install.sh
    --after-install $TEMPLATEDIR/install/post_install.sh
    --after-remove $TEMPLATEDIR/install/post_remove.sh
)
[ -z $PKGCONFLICTS ] || FPMCOMMON+=( --conflicts $PKGCONFLICTS )
FPMRPM=(
    --before-upgrade $TEMPLATEDIR/install/post_remove.sh
    --after-upgrade $TEMPLATEDIR/install/post_install.sh
)

cd $BUILDDIR
echo "Removing old packages"
rm -f *.deb
rm -f *.rpm

for arch in ${!ARCHTGZDIRS[@]}
do
    archDir=${ARCHTGZDIRS[$arch]}
    echo "Creating DEB Package for $arch"
    fpm "${FPMCOMMON[@]}" -C $archDir -a $arch -t deb "${CONFIGFILES[@]}" ./=/opt/tyk-gateway
    echo "Creating RPM Package for $arch"
    fpm "${FPMCOMMON[@]}" "${FPMRPM[@]}" -C $archDir -a $arch -t rpm "${CONFIGFILES[@]}" ./=/opt/tyk-gateway

    rpmName="$PKGNAME-$VERSION-1.${arch/amd64/x86_64}.rpm"
    echo "Signing $arch RPM"
    $BUILDTOOLSDIR/rpm-sign.sh $rpmName
done
