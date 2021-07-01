#!/usr/bin/env bash

# Get the GPG fingerprint with gpg --with-keygrip --list-secret-keys
if [[ -z "${PKG_SIGNING_KEY}" || -z "${NFPM_STD_PASSPHRASE}" || -z "${GPG_FINGERPRINT}" ]]; then
    echo "No private key set, packages cannnot be signed. Set PKG_SIGNING_KEY, NFPM_STD_PASSPHRASE and GPG_FINGERPRINT"
    exit 1
fi

echo Configuring gpg-agent to accept a passphrase
mkdir ~/.gnupg && chmod 700 ~/.gnupg
cat > ~/.gnupg/gpg-agent.conf <<EOF
disable-scdaemon
default-cache-ttl 3600
max-cache-ttl 3600
allow-preset-passphrase
debug-level expert
log-file /gpg-agent.log
allow-loopback-pinentry
EOF
gpg-connect-agent reloadagent /bye
# This is what makes gpg2 not attempt pinentry
gpg-connect-agent --verbose "OPTION pinentry-mode=loopback" /bye

echo Configuring gpg not to look for a tty
cat > ~/.gnupg/gpg.conf <<EOF
no-tty
EOF

# nfpm demands this on the filesystem
echo "$PKG_SIGNING_KEY" > tyk.io.signing.key

chmod 400 tyk.io.signing.key
# archive signing can work with gpg
/usr/lib/gnupg2/gpg-preset-passphrase --passphrase $NFPM_STD_PASSPHRASE --preset $GPG_FINGERPRINT
gpg --import --batch --yes tyk.io.signing.key || ( cat /gpg-agent.log; exit 1 )
