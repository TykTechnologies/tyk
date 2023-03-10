#!/bin/bash
set -e

# Run this script to regenerate `log.yml`

function rewriteLog() {
	local prefix=$1
	local log=$2
	sed -ze "s/:prefix:/$prefix/g;s/:log:/$log/g" log.yml.tpl
}

function rewriteLogs() {
	echo "---"
	echo "# == Special thanks to Zaid Albirawi =="
	echo
	echo "rules:"

	# For each prefixed logger with a global variable...

	rewriteLog "main" "mainLog"
	rewriteLog "certs" "certLog"
	rewriteLog "pub-sub" "pubSubLog"
	rewriteLog "dashboard" "dashLog"

	rewriteLog "api" "apiLog"
	rewriteLog "host-check-mgr" "hostCheckLog"
	rewriteLog "coprocess" "coprocessLog"
	rewriteLog "python" "pythonLog"
	rewriteLog "webhooks" "webhookLog"
}

rewriteLogs > log.yml