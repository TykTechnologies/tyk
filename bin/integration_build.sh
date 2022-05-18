#!/bin/bash

set -ex

: ${SIGNKEY:="12B5D62C28F57592D1575BD51ED14C59E37DAC20"}
: ${BUILDPKGS:="1"}
: ${ARCH:=amd64}
: ${PKG_PREFIX:=tyk}
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
         ${bdir}/templates/playground \
         ${bdir}/policies \
         ${bdir}/utils \
         ${bdir}/install

cp apps/app_sample.json ${bdir}/apps
cp templates/*.json ${bdir}/templates
cp templates/playground/index.html ${bdir}/templates/playground
cp templates/playground/playground.js ${bdir}/templates/playground
cp -R install/* ${bdir}/install
cp middleware/*.js ${bdir}/middleware
cp event_handlers/sample/*.js ${bdir}/event_handlers/sample
cp policies/*.json ${bdir}/policies
cp tyk.conf.example ${bdir}
cp tyk.conf.example ${bdir}/tyk.conf
cp -R coprocess ${bdir}

echo "Building Tyk binaries"
go build -tags 'goplugin'
mv tyk ${bdir}

echo "Making tarball"
tar -C $bdir -pczf ${PKG_PREFIX}-${ARCH}-${VERSION}.tar.gz .

# Nothing more to do if we're not going to build packages
[ $BUILDPKGS != "1" ] && exit 0

CONFIGFILES=(
    --config-files /opt/${PKG_PREFIX}/apps
    --config-files /opt/${PKG_PREFIX}/templates
    --config-files /opt/${PKG_PREFIX}/middleware
    --config-files /opt/${PKG_PREFIX}/event_handlers
    --config-files /opt/${PKG_PREFIX}/js
    --config-files /opt/${PKG_PREFIX}/policies
    --config-files /opt/${PKG_PREFIX}/tyk.conf
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
fpm "${FPMCOMMON[@]}" -a $ARCH -t deb "${CONFIGFILES[@]}" ./=/opt/${PKG_PREFIX}
echo "Creating RPM Package for $ARCH"
fpm "${FPMCOMMON[@]}" "${FPMRPM[@]}" -a $ARCH -t rpm "${CONFIGFILES[@]}" ./=/opt/${PKG_PREFIX}

if [ $BUILDPKGS == "1" ]; then
    echo "Signing $ARCH RPM"
    rpm --define "%_gpg_name Team Tyk (package signing) <team@tyk.io>" \
        --define "%__gpg /usr/bin/gpg" \
        --addsign *.rpm || (cat /tmp/gpg-agent.log; exit 1)
    echo "Signing $ARCH DEB"
    dpkg-sig --sign builder -k $SIGNKEY $i || (cat /tmp/gpg-agent.log; exit 1)
fi
