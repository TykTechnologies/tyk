package gateway

import (
	"testing"
)

const consul = `
[{
	"Node": "foobar",
	"Address": "10.1.10.12",
	"ServiceID": "redis",
	"ServiceName": "redis",
	"ServicePort": 8000
},
{
	"Node": "foobar2",
	"Address": "10.1.10.13",
	"ServiceID": "redis",
	"ServiceName": "redis",
	"ServicePort": 8000
}]
`

const eureka_real = `{
	"application": {
		"name": "ROUTE",
		"instance": [{
			"hostName": "ip-172-31-57-136",
			"app": "ROUTE",
			"ipAddr": "172.31.57.136",
			"status": "UP",
			"overriddenstatus": "UNKNOWN",
			"port": {
				"@enabled": "true",
				"$": "60565"
			},
			"securePort": {
				"@enabled": "false",
				"$": "443"
			},
			"countryId": 1,
			"dataCenterInfo": {
				"@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
				"name": "MyOwn"
			},
			"leaseInfo": {
				"renewalIntervalInSecs": 10,
				"durationInSecs": 10,
				"registrationTimestamp": 1460471383902,
				"lastRenewalTimestamp": 1460471403565,
				"serviceUpTimestamp": 1460471383340
			},
			"metadata": {
				"instanceId": "route:f673c15eebfc456a3c679a55d234a8ca",
				"payment": "perCall",
				"providerName": "MisterA"
			},
			"homePageUrl": "http:\/\/ip-172-31-57-136:60565\/",
			"statusPageUrl": "http:\/\/ip-172-31-57-136:60565\/info",
			"healthCheckUrl": "http:\/\/ip-172-31-57-136:60565\/health",
			"vipAddress": "route",
			"lastUpdatedTimestamp": 1460471383902,
			"lastDirtyTimestamp": 1460471429751,
			"actionType": "ADDED"
		}, {
			"hostName": "ip-172-31-13-37",
			"app": "ROUTE",
			"ipAddr": "172.31.13.37",
			"status": "UP",
			"overriddenstatus": "UNKNOWN",
			"port": {
				"@enabled": "true",
				"$": "50045"
			},
			"securePort": {
				"@enabled": "false",
				"$": "443"
			},
			"countryId": 1,
			"dataCenterInfo": {
				"@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
				"name": "MyOwn"
			},
			"leaseInfo": {
				"renewalIntervalInSecs": 10,
				"durationInSecs": 10,
				"registrationTimestamp": 1460471387114,
				"lastRenewalTimestamp": 1460471407062,
				"serviceUpTimestamp": 1460471386750
			},
			"metadata": {
				"instanceId": "route:838ba7845f1fd63d94c10ca9efdf77a5",
				"payment": "flat",
				"providerName": "MissB"
			},
			"homePageUrl": "http:\/\/ip-172-31-13-37:50045\/",
			"statusPageUrl": "http:\/\/ip-172-31-13-37:50045\/info",
			"healthCheckUrl": "http:\/\/ip-172-31-13-37:50045\/health",
			"vipAddress": "route",
			"lastUpdatedTimestamp": 1460471387114,
			"lastDirtyTimestamp": 1460471360189,
			"actionType": "ADDED"
		}]
	}
}`

const nested_consul = `
[{
	"Name": "beep",
	"Data": "{\"hostname\": \"httpbin1.org\", \"port\": \"80\"}"
},
{
	"Name": "boop",
	"Data": "{\"hostname\": \"httpbin2.org\", \"port\": \"80\"}"
}]`

const etcd = `{
	"action": "get",
	"node": {
		"key": "/services/single",
		"value": "httpbin.org:6000",
		"modifiedIndex": 6,
		"createdIndex": 6
	}
}`

const nested = `{
	"action": "get",
	"node": {
		"key": "/services/single",
		"value": "{\"hostname\": \"httpbin.org\", \"port\": \"80\"}",
		"modifiedIndex": 6,
		"createdIndex": 6
	}
}`

const nested_list = `{
	"action": "get",
	"node": {
		"key": "/services/single",
		"value": "[{\"hostname\": \"httpbin.org\", \"port\": \"80\"}, {\"hostname\": \"httpbin2.org\", \"port\": \"80\"}]",
		"modifiedIndex": 6,
		"createdIndex": 6
	}
}`

const mesosphere = `{
	"tasks": [{
		"id": "myservice.7fc21d4c-eabb-11e5-b381-066c48d09c8f",
		"host": "httpbin.org",
		"ports": [80],
		"startedAt": "2016-03-15T14:37:55.941Z",
		"stagedAt": "2016-03-15T14:37:52.792Z",
		"version": "2016-03-15T14:37:52.726Z",
		"slaveId": "d70867df-fdb2-4889-abeb-0829c742fded-S2",
		"appId": "/httpbin"
	}]
}`

func configureService(name string, sd *ServiceDiscovery) string {
	switch name {
	case "consul":
		sd.isTargetList = true
		sd.endpointReturnsList = true
		sd.portSeperate = true
		sd.dataPath = "Address"
		sd.portPath = "ServicePort"
		return consul
	case "etcd":
		sd.dataPath = "node.value"
		return etcd
	case "nested":
		sd.isNested = true
		sd.portSeperate = true
		sd.dataPath = "hostname"
		sd.parentPath = "node.value"
		sd.portPath = "port"
		return nested
	case "nested_list":
		sd.isNested = true
		sd.isTargetList = true
		sd.portSeperate = true
		sd.dataPath = "hostname"
		sd.parentPath = "node.value"
		sd.portPath = "port"
		return nested_list
	case "nested_consul":
		sd.isNested = true
		sd.isTargetList = true
		sd.endpointReturnsList = true
		sd.portSeperate = true
		sd.dataPath = "hostname"
		sd.parentPath = "Data"
		sd.portPath = "port"
		return nested_consul
	case "mesosphere":
		sd.isTargetList = true
		sd.portSeperate = true
		sd.dataPath = "host"
		sd.parentPath = "tasks"
		sd.portPath = "ports"
		return mesosphere
	case "eureka":
		sd.isTargetList = true
		sd.portSeperate = true
		sd.dataPath = "hostName"
		sd.parentPath = "application.instance"
		sd.portPath = "port.$"
		return eureka_real
	}
	return ""
}

func TestServiceDiscovery_EUREKA(t *testing.T) {
	sd := ServiceDiscovery{}
	rawData := configureService("eureka", &sd)
	data, err := sd.ProcessRawData(rawData)

	if err != nil {
		t.Error(err)
	}

	arr := []string{"ip-172-31-57-136:60565", "ip-172-31-13-37:50045"}

	if data.Len() != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range data.All() {
		if v != arr[i] {
			err := "Value is wrong, should be: " + arr[i] + " have: " + v
			t.Error(err)
		}
	}

}

func TestServiceDiscovery_CONSUL(t *testing.T) {
	sd := ServiceDiscovery{}
	rawData := configureService("consul", &sd)
	data, err := sd.ProcessRawData(rawData)

	if err != nil {
		t.Error(err)
	}

	arr := []string{"10.1.10.12:8000", "10.1.10.13:8000"}

	if data.Len() != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range data.All() {
		if v != arr[i] {
			err := "Value is wrong, should be: " + arr[i] + " have: " + v
			t.Error(err)
		}
	}

}

func TestServiceDiscovery_NESTED_CONSUL(t *testing.T) {
	sd := ServiceDiscovery{}
	rawData := configureService("nested_consul", &sd)
	data, err := sd.ProcessRawData(rawData)

	if err != nil {
		t.Error(err)
	}

	arr := []string{"httpbin1.org:80", "httpbin2.org:80"}

	if data.Len() != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range data.All() {
		if v != arr[i] {
			err := "Value is wrong, should be: " + arr[i] + " have: " + v
			t.Error(err)
		}
	}

}

func TestServiceDiscovery_ETCD_NESTED_LIST(t *testing.T) {
	sd := ServiceDiscovery{}
	rawData := configureService("nested_list", &sd)
	data, err := sd.ProcessRawData(rawData)

	if err != nil {
		t.Error(err)
	}

	arr := []string{"httpbin.org:80", "httpbin2.org:80"}

	if data.Len() != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range data.All() {
		if v != arr[i] {
			err := "Value is wrong, should be: " + arr[i] + " have: " + v
			t.Error(err)
		}
	}

}

func TestServiceDiscovery_ETCD_NESTED_NOLIST(t *testing.T) {
	sd := ServiceDiscovery{}
	rawData := configureService("nested", &sd)
	data, err := sd.ProcessRawData(rawData)

	if err != nil {
		t.Error(err)
	}

	host, _ := data.GetIndex(0)

	tVal := "httpbin.org:80"

	if tVal != host {
		err := "Value is wrong, should be: " + tVal + " have: " + host
		t.Error(err)
	}

}

func TestServiceDiscovery_ETCD_NOLIST(t *testing.T) {
	sd := ServiceDiscovery{}
	rawData := configureService("etcd", &sd)
	data, err := sd.ProcessRawData(rawData)

	if err != nil {
		t.Error(err)
	}

	host, _ := data.GetIndex(0)

	tVal := "httpbin.org:6000"

	if tVal != host {
		err := "Value is wrong, should be: " + tVal + " have: " + host
		t.Error(err)
	}

}

func TestServiceDiscovery_MESOSPHERE(t *testing.T) {
	sd := ServiceDiscovery{}
	rawData := configureService("mesosphere", &sd)
	data, err := sd.ProcessRawData(rawData)

	if err != nil {
		t.Error(err)
	}

	arr := []string{"httpbin.org:80"}

	if data.Len() != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range data.All() {
		if v != arr[i] {
			err := "Value is wrong, should be: " + arr[i] + " have: " + v
			t.Error(err)
		}
	}

}
