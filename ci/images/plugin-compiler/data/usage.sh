#!/bin/bash
set -eo pipefail
shopt -s nullglob
set -x

usage(){
    # 1. In the machine that has internet, run;
    #      bash usage.sh /path/to/plugin/source/code /tmp/myGoProxy v5.2.2
    # 2. In the machine that has NO internet, download the custom plugin compiler.
    #      docker pull komuw/tyk-plugin-compiler:v5.2.2
    # 3. Copy the directory `/tmp/myGoProxy` to the machine that has no internet.
    # 4. In the machine that has NO internet, run;
    #      cd /path/to/directory/with/plugin/code
    #      docker run --env GO_USE_PROXY=1 --volume /path/to/plugin/source/code:/plugin-source --volume /tmp/myGoProxy:/tmp/myGoProxy komuw/tyk-plugin-compiler:v5.2.2 CustomGoPlugin.so
    #
    printf "\n\tusage:\n bash usage.sh /path/to/plugin/source/code /tmp/myGoProxy v5.2.2 \n"
    exit 1
}

THE_GO_VERSION=$(go version | awk '{print $3;}')
if [[ $THE_GO_VERSION == *"1.19"* ]]; then
    echo -n  ''
else
    echo "The Go version you are using is not v1.19, exiting" && usage;
fi

PLUGIN_DIR=${1:-NotSet}
if [ "$PLUGIN_DIR" == "NotSet"  ]; then
    printf "\n\n PLUGIN_DIR should not be empty\n"
    usage
fi

OUR_GO_PROXY=${2:-NotSet}
if [ "$OUR_GO_PROXY" == "NotSet"  ]; then
    printf "\n\n OUR_GO_PROXY should not be empty\n"
    usage
fi

TYK_VERSION=${3:-NotSet}
if [ "$TYK_VERSION" == "NotSet"  ]; then
    printf "\n\n TYK_VERSION should not be empty\n"
    usage
fi


printf "\n\n PLUGIN_DIR=${PLUGIN_DIR} \n TYK_VERSION=${TYK_VERSION} \n OUR_GO_PROXY=${OUR_GO_PROXY} \n THE_GO_VERSION=${THE_GO_VERSION} \n\n"

# update GOPROXY to have all the required modules for tyk gateway at the given tag.
set_tyk_modules(){
	rm -rf "/tmp/${TYK_VERSION}.zip"
	rm -rf "/tmp/${TYK_VERSION}"
	wget --no-check-certificate -nc --output-document="/tmp/${TYK_VERSION}.zip" "https://github.com/TykTechnologies/tyk/archive/refs/tags/${TYK_VERSION}.zip"
	unzip "/tmp/${TYK_VERSION}.zip" -d "/tmp/"
	rm -rf "/tmp/${TYK_VERSION}.zip"
	mv /tmp/tyk-* "/tmp/${TYK_VERSION}"
	cd "/tmp/${TYK_VERSION}"
	pwd
	unset GOPROXY
	unset GOPATH
	export GOPROXY='https://proxy.golang.org,direct'
	export GOPATH=${OUR_GO_PROXY}
	go mod download
	go mod tidy
}
set_tyk_modules


# update GOPROXY to have all the required modules for the plugin.
set_plugin_modules(){
	cd ${PLUGIN_DIR}
    {
	    go mod init github.com/example/plugin
    } || {
        echo -n '' # already a module
    }
	go get -d github.com/TykTechnologies/tyk@`git ls-remote https://github.com/TykTechnologies/tyk.git refs/tags/${TYK_VERSION} | awk '{print $1;}'`
	unset GOPROXY
	unset GOPATH
	export GOPROXY='https://proxy.golang.org,direct'
	export GOPATH=${OUR_GO_PROXY}
	go mod download
	go mod tidy
	tree ${OUR_GO_PROXY}/pkg/mod/cache/download
	unset GOPROXY
	unset GOPATH
}
set_plugin_modules

# This should be run in the machine with no internet.
build_plugin(){
    cd ${PLUGIN_DIR}
    docker \
      run \
      --env GO_USE_PROXY=1 \
      --volume ${PLUGIN_DIR}:/plugin-source \
      --volume ${OUR_GO_PROXY}:/tmp/myGoProxy \
      tt-comp CustomGoPlugin.so
}
# build_plugin
