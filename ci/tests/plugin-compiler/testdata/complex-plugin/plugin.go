package main

import (
	"example.com/basic-plugin/analytics"
	"example.com/basic-plugin/plugin"
)

var MyPluginPre = plugin.MyPluginPre
var MyPluginAuthCheck = plugin.MyPluginAuthCheck
var MyPluginPostKeyAuth = plugin.MyPluginPostKeyAuth
var MyPluginPost = plugin.MyPluginPost
var MyPluginResponse = plugin.MyPluginResponse
var MyPluginPerPathFoo = plugin.MyPluginPerPathFoo
var MyPluginPerPathBar = plugin.MyPluginPerPathBar
var MyPluginPerPathResp = plugin.MyPluginPerPathResp

var MyAnalyticsPluginDeleteHeader = analytics.MyAnalyticsPluginDeleteHeader
var MyAnalyticsPluginMaskJSONLoginBody = analytics.MyAnalyticsPluginMaskJSONLoginBody
