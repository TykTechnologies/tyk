#!/bin/bash

# This file is deprecated in favour of .goreleaser.yml
# Automation in .g/w/release.yml

set -ex

: ${ORGDIR:="/go/src/github.com/TykTechnologies"}
: ${SOURCEBINPATH:="${ORGDIR}/tyk"}
: ${SIGNKEY:="12B5D62C28F57592D1575BD51ED14C59E37DAC20"}
: ${BUILDPKGS:="1"}
: ${SIGNPKGS:="1"}
: ${PKGNAME:="tyk-gateway"}
BUILDTOOLSDIR=$SOURCEBINPATH/build_tools
BUILDDIR=$SOURCEBINPATH/build
CIDIR=$SOURCEBINPATH/ci

echo "Set version number"
: ${VERSION:=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "$1\.$2\.$3"' version.go)}

if [ $BUILDPKGS == "1" ]; then
    echo Configuring gpg-agent-config to accept a passphrase
    mkdir ~/.gnupg && chmod 700 ~/.gnupg
    cat >> ~/.gnupg/gpg-agent.conf <<EOF
allow-preset-passphrase
debug-level expert
log-file /tmp/gpg-agent.log
EOF
    gpg-connect-agent reloadagent /bye

    echo "Importing signing key"
    gpg --list-keys | grep -w $SIGNKEY && echo "Key exists" || gpg --batch --import $BUILDTOOLSDIR/tyk.io.signing.key
    bash $CIDIR/bin/unlock-agent.sh $SIGNKEY
fi

echo "Prepare the release directories"

export SOURCEBIN=tyk

declare -A ARCHTGZDIRS
ARCHTGZDIRS=(
    [amd64]=$BUILDDIR/amd64/tgz/tyk.linux.amd64-$VERSION
)

DESCRIPTION="Tyk Open Source API Gateway written in Go"
echo "Starting Tyk build"
cd $SOURCEBINPATH

echo "Moving vendor dir to GOPATH"
yes | cp -r vendor ${GOPATH}/src/ && rm -rf vendor

echo "Blitzing TGZ dirs"
for arch in ${!ARCHTGZDIRS[@]}
do
    rm -rf ${ARCHTGZDIRS[$arch]}
    mkdir -p ${ARCHTGZDIRS[$arch]}
done

echo "Building Tyk binaries"
gox -tags 'goplugin' -osarch="linux/amd64" -cgo

TEMPLATEDIR=${ARCHTGZDIRS[amd64]}
echo "Prepping TGZ Dirs"
mkdir -p $TEMPLATEDIR/apps
mkdir -p $TEMPLATEDIR/js
mkdir -p $TEMPLATEDIR/middleware
mkdir -p $TEMPLATEDIR/middleware/python
mkdir -p $TEMPLATEDIR/middleware/lua
mkdir -p $TEMPLATEDIR/event_handlers
mkdir -p $TEMPLATEDIR/event_handlers/sample
mkdir -p $TEMPLATEDIR/templates/playground
mkdir -p $TEMPLATEDIR/policies
mkdir -p $TEMPLATEDIR/utils
mkdir -p $TEMPLATEDIR/install

cp $SOURCEBINPATH/apps/app_sample.json $TEMPLATEDIR/apps
cp $SOURCEBINPATH/templates/*.json $TEMPLATEDIR/templates
cp -R $SOURCEBINPATH/templates/playground/* $TEMPLATEDIR/templates/playground
cp -R $SOURCEBINPATH/ci/install/* $TEMPLATEDIR/install
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
    mv tyk_linux_${arch} $archDir/$SOURCEBIN
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

    if [ $SIGNPKGS == "1" ]; then
        echo "Signing $arch RPM"
        rpm --define "%_gpg_name Team Tyk (package signing) <team@tyk.io>" \
            --define "%__gpg /usr/bin/gpg" \
            --addsign *.rpm || (cat /tmp/gpg-agent.log; exit 1)
        echo "Signing $arch DEB"
        for i in *.deb
        do
            dpkg-sig --sign builder -k $SIGNKEY $i || (cat /tmp/gpg-agent.log; exit 1)
        done
    fi
done
