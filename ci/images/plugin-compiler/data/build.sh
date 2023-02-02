#!/bin/bash
set -xe

CURRENTVERS=$(perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"' $TYK_GW_PATH/gateway/version.go)
plugin_name=$1
plugin_id=$2

function usage() {
    cat <<EOF
To build a plugin:
      $0 <plugin_name> [<plugin_id>]

<plugin_id> is  optional
If you want to build for a separate platform, please provide GOARCH and GOOS as docker env vars.
EOF
}

if [ -z "$plugin_name" ]; then
    usage
    exit 1
fi

# if GOOS and GOENV is not set from docker env, derive it from the host
# golang-X image.
if [[ $GOOS == "" ]] && [[ $GOARCH == "" ]]; then
  GOOS=$(go env GOOS)
  GOARCH=$(go env GOARCH)
fi


# if arch and os present then update the name of file with those params
if [[ $GOOS != "" ]] && [[ $GOARCH != "" ]]; then
  plugin_name="${plugin_name%.*}_${CURRENTVERS}_${GOOS}_${GOARCH}.so"
fi

echo "Building plugin: $plugin_name"

cd $TYK_GW_PATH
go mod tidy
go mod download
go list -m -f '{{ if not .Main }}{{ .Path }} {{ .Version }}{{ end }}' all > dependencies.txt

cd $PLUGIN_SOURCE_PATH
go get

# Get plugin dependencies
go list -m -f '{{ if not .Main }}{{ .Path }} {{ .Version }}{{ end }}' all > dependencies.txt


echo $GIT_COMMIT
go mod edit -replace github.com/TykTechnologies/tyk=github.com/TykTechnologies/tyk@$GIT_COMMIT

# Run a final go mod tidy to make sure that the go.sum entries are correct for
# all replaced dependencies.
go mod tidy

# for any shared dependency, pin the version to Tyk gateway version
awk 'NR==FNR{seen[$1]=$2; next} seen[$1] && seen[$1] != $2' $PLUGIN_SOURCE_PATH/dependencies.txt $TYK_GW_PATH/dependencies.txt | while read PKG VER; do
  go mod edit -replace $PKG=$PKG@$VER
done

#go mod vendor
rm -rf ./vendor


echo $GOARCH $GOOS

# set appropriate X-build gcc binary for arm64.
if [[ $GOARCH == "arm64" ]] && [[ $GOOS == "linux" ]] ; then
    CC=aarch64-linux-gnu-gcc
else
    CC=$(go env CC)
fi

CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH CC=$CC  go build -trimpath -buildmode=plugin -gcflags="all=-N -l" -o $plugin_name
