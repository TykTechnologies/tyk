#!/bin/bash

set -ex

: ${SIGNKEY:="12B5D62C28F57592D1575BD51ED14C59E37DAC20"}
: ${BUILDPKGS:="1"}
: ${ARCH:=amd64}

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
    bash $BUILDTOOLSDIR/unlock-agent.sh $SIGNKEY
fi

DESCRIPTION="Tyk Open Source API Gateway written in Go"

bdir=build
echo "Creating build dir: $bdir"

mkdir -p ${bdir}/apps \
         ${bdir}/js \
         ${bdir}/middleware \
         ${bdir}/middleware/python \
         ${bdir}/middleware/lua \
         ${bdir}/event_handlers \
         ${bdir}/event_handlers/sample \
         ${bdir}/templates \
         ${bdir}/policies \
         ${bdir}/utils \
         ${bdir}/install

cp apps/app_sample.json ${bdir}/apps
cp templates/*.json ${bdir}/templates
cp -R install/* ${bdir}/install
cp middleware/*.js ${bdir}/middleware
cp event_handlers/sample/*.js ${bdir}/event_handlers/sample
cp policies/*.json ${bdir}/policies
cp tyk.conf.example ${bdir}
cp tyk.conf.example ${bdir}/tyk.conf
cp -R coprocess ${bdir}

echo "Building Tyk binaries"
go build -tags 'goplugin' -mod=vendor && mv tyk ${bdir}

echo "Making tarball"
tar -C $bdir -pczf tyk-${ARCH}-${VERSION}.tar.gz .

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

cd $bdir
echo "Creating DEB Package for $ARCH"
fpm "${FPMCOMMON[@]}" -a $ARCH -t deb "${CONFIGFILES[@]}" ./=/opt/tyk-gateway
echo "Creating RPM Package for $ARCH"
fpm "${FPMCOMMON[@]}" "${FPMRPM[@]}" -a $ARCH -t rpm "${CONFIGFILES[@]}" ./=/opt/tyk-gateway

if [ $BUILDPKGS == "1" ]; then
    echo "Signing $ARCH RPM"
    rpm --define "%_gpg_name Team Tyk (package signing) <team@tyk.io>" \
        --define "%__gpg /usr/bin/gpg" \
        --addsign *.rpm || (cat /tmp/gpg-agent.log; exit 1)
    echo "Signing $ARCH DEB"
    dpkg-sig --sign builder -k $SIGNKEY $i || (cat /tmp/gpg-agent.log; exit 1)
fi
