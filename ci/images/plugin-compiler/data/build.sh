#!/bin/bash
set -e

GATEWAY_VERSION=$(echo $GITHUB_TAG | perl -n -e'/v(\d+).(\d+).(\d+)/'' && print "v$1\.$2\.$3"')

# Plugin compiler arguments:
#
# - 1. plugin_name = vendor-plugin.so
# - 2. plugin_id = optional, sets build folder to `/opt/plugin_{plugin_name}{plugin_id}`
# - 3. GOOS = optional override of GOOS
# - 4. GOARCH = optional override of GOARCH
#
# The script will build a plugin named according to the following:
#
# - `{plugin_name%.*}_{GATEWAY_VERSION}_{GOOS}_{GOARCH}.so`
#
# If GOOS and GOARCH are not set, it will build `{plugin_name}`.
#
# Example command: ./build.sh
# Example output: tyk-extras_5.0.0_linux_amd64.so

plugin_name=$1
plugin_id=$2
GOOS=${3:-$(go env GOOS)}
GOARCH=${4:-$(go env GOARCH)}

# Some defaults that can be overriden with env
WORKSPACE_ROOT=$(dirname $TYK_GW_PATH)

PLUGIN_SOURCE_PATH=${PLUGIN_SOURCE_PATH:-"/plugin-source"}
PLUGIN_BUILD_PATH=${PLUGIN_BUILD_PATH:-"${WORKSPACE_ROOT}/plugin_${plugin_name%.*}$plugin_id"}

function usage() {
    cat <<EOF
To build a plugin:
      $0 <plugin_name> <plugin_id>

<plugin_id> is optional
EOF
}

if [ -z "$plugin_name" ] ; then
    usage
    exit 1
fi

# Set up arm64 cross build
CC=$(go env CC)
if [[ $GOARCH == "arm64" ]] && [[ $GOOS == "linux" ]] ; then
	CC=aarch64-linux-gnu-gcc
fi

# if arch and os present then update the name of file with those params
if [[ $GOOS != "" ]] && [[ $GOARCH != "" ]] ; then
  plugin_name="${plugin_name%.*}_${GATEWAY_VERSION}_${GOOS}_${GOARCH}.so"
fi

# Copy plugin source into plugin build folder.
mkdir -p $PLUGIN_BUILD_PATH
yes | cp -r $PLUGIN_SOURCE_PATH/* $PLUGIN_BUILD_PATH || true


# Dump settings for inspection

echo "PLUGIN_BUILD_PATH: ${PLUGIN_BUILD_PATH}"
echo "PLUGIN_SOURCE_PATH: ${PLUGIN_SOURCE_PATH}"

if [[ "$DEBUG" == "1" ]] ; then
	set -x
fi

# Go to plugin build path
cd $PLUGIN_BUILD_PATH

if [[ "$DEBUG" == "1" ]] ; then
	git config --global init.defaultBranch main
	git config --global user.name "Tit Petric"
	git config --global user.email "tit@tyk.io"
	git init
	git add .
	git commit -m "initial import" .
fi

# ensureGoMod rewrites a go module based on plugin_id if available.
function ensureGoMod {
	NEW_MODULE=tyk.internal/tyk_plugin${plugin_id}

	# Create go.mod if it doesn't exist.
	if [ ! -f "go.mod" ] ; then
		echo "INFO: Creating go.mod"
		go mod init $NEW_MODULE
		return
	fi

	# Keep go.mod as is if plugin_id is empty.
	if [ -z "${plugin_id}" ] ; then
		echo "INFO: No plugin id provided, keeping go.mod as is"
		return
	fi

	# Replace provided go.mod module path with plugin id path
	OLD_MODULE=$(go mod edit -json | jq .Module.Path -r)

	case "$OLD_MODULE" in
		# module has a domain, less chance of conflicts
		*.*)
		;;

		# warn if module doesn't have a domain or path
		*)
		echo "WARN: Plugin go.mod module doesn't contain a dot, consider amending it to prevent conflicts"
		echo "      Current value: $OLD_MODULE"
		echo "    Suggested value: github.com/org/plugin-repo"
		;;
	esac

	# Replace go.mod module
	go mod edit -module $NEW_MODULE

	# Replace import paths
	find ./ -type f -name '*.go' -exec sed -i -e "s,\"${OLD_MODULE},\"${NEW_MODULE},g" {} \;

}

ensureGoMod

# Create worspace after ensuring go.mod exists
cd $WORKSPACE_ROOT
go work init ./tyk
go work use ./$(basename $PLUGIN_BUILD_PATH)

# Go to plugin build path
cd $PLUGIN_BUILD_PATH

if [[ "$GO_GET" == "1" ]] ; then
	go get github.com/TykTechnologies/tyk@${GITHUB_SHA}
fi

if [[ "$GO_TIDY" == "1" ]] ; then
	go mod tidy
fi

if [[ "$DEBUG" == "1" ]] ; then
	git add .
	git diff --cached
fi

if [ -n "$BUILD_TAG" ]; then
    CC=$CC CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH go build -buildmode=plugin -trimpath -tags=$BUILD_TAG -o $plugin_name
else
    CC=$CC CGO_ENABLED=1 GOOS=$GOOS GOARCH=$GOARCH go build -buildmode=plugin -trimpath -o $plugin_name
fi

set +x

mv *.so $PLUGIN_SOURCE_PATH

# Clean up workspace
rm -f $WORKSPACE_ROOT/go.work
