package main

import (
	"testing"
)

var consul string = `
[
  {
    "Node": "foobar",
    "Address": "10.1.10.12",
    "ServiceID": "redis",
    "ServiceName": "redis",
    "ServiceTags": null,
    "ServiceAddress": "",
    "ServicePort": 8000
  },
  {
    "Node": "foobar2",
    "Address": "10.1.10.13",
    "ServiceID": "redis",
    "ServiceName": "redis",
    "ServiceTags": null,
    "ServiceAddress": "",
    "ServicePort": 8000
  }
]
`

var eureka = `
{
	"application": {
		"name": "ROUTE",
		"instance": [{
			"hostName": "ip-172-31-57-136",
			"ipAddr": "172.31.57.136",
			"port": {
				"@enabled": "true",
				"$": "47954"
			}

		}, {
			"hostName": "ip-172-31-13-37",
			"app": "ROUTE",
			"ipAddr": "172.31.13.37",
			"port": {
				"@enabled": "true",
				"$": "34406"
			}
		}]
	}
}
`

var nested_consul string = `
[
  {
    "Name": "beep",
    "Data": "{\"hostname\": \"httpbin1.org\", \"port\": \"80\"}"
  },
  {
    "Name": "boop",
    "Data": "{\"hostname\": \"httpbin2.org\", \"port\": \"80\"}"
  }
]
`

var etcd string = `
{
    "action": "get",
    "node": {
        "key": "/services/single",
        "value": "httpbin.org:6000",
        "modifiedIndex": 6,
        "createdIndex": 6
    }
}
`

var nested string = `
{
    "action": "get",
    "node": {
        "key": "/services/single",
        "value": "{\"hostname\": \"httpbin.org\", \"port\": \"80\"}",
        "modifiedIndex": 6,
        "createdIndex": 6
    }
}
`

var nested_list string = `
{
    "action": "get",
    "node": {
        "key": "/services/single",
        "value": "[{\"hostname\": \"httpbin.org\", \"port\": \"80\"}, {\"hostname\": \"httpbin2.org\", \"port\": \"80\"}]",
        "modifiedIndex": 6,
        "createdIndex": 6
    }
}
`

var mesosphere string = `
{
 "tasks": [{
  "id": "myservice.7fc21d4c-eabb-11e5-b381-066c48d09c8f",
  "host": "httpbin.org",
  "ipAddresses": [],
  "ports": [80],
  "startedAt": "2016-03-15T14:37:55.941Z",
  "stagedAt": "2016-03-15T14:37:52.792Z",
  "version": "2016-03-15T14:37:52.726Z",
  "slaveId": "d70867df-fdb2-4889-abeb-0829c742fded-S2",
  "appId": "/httpbin"
 }]
}
`

func configureService(name string, sd *ServiceDiscovery) string {
	log.Info("Getting ", name)
	switch name {
	case "consul":
		sd.isNested = false
		sd.isTargetList = true
		sd.endpointReturnsList = true
		sd.portSeperate = true
		sd.dataPath = "Address"
		sd.parentPath = ""
		sd.portPath = "ServicePort"
		return consul
	case "etcd":
		sd.isNested = false
		sd.isTargetList = false
		sd.endpointReturnsList = false
		sd.portSeperate = false
		sd.dataPath = "node.value"
		sd.parentPath = ""
		sd.portPath = ""
		return etcd
	case "nested":
		sd.isNested = true
		sd.isTargetList = false
		sd.endpointReturnsList = false
		sd.portSeperate = true
		sd.dataPath = "hostname"
		sd.parentPath = "node.value"
		sd.portPath = "port"
		return nested
	case "nested_list":
		sd.isNested = true
		sd.isTargetList = true
		sd.endpointReturnsList = false
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
		sd.isNested = false
		sd.isTargetList = true
		sd.endpointReturnsList = false
		sd.portSeperate = true
		sd.dataPath = "host"
		sd.parentPath = "tasks"
		sd.portPath = "ports"
		return mesosphere
	case "eureka":
		sd.isNested = false
		sd.isTargetList = true
		sd.endpointReturnsList = false
		sd.portSeperate = true
		sd.dataPath = "hostName"
		sd.parentPath = "application.instance"
		sd.portPath = "port.$"
		return eureka
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

	var thisList *[]string
	thisList = data.(*[]string)

	arr := []string{"ip-172-31-57-136:47954", "ip-172-31-13-37:34406"}

	if len(*thisList) != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range *thisList {
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

	var thisList *[]string
	thisList = data.(*[]string)

	arr := []string{"10.1.10.12:8000", "10.1.10.13:8000"}

	if len(*thisList) != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range *thisList {
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

	var thisList *[]string
	thisList = data.(*[]string)

	arr := []string{"httpbin1.org:80", "httpbin2.org:80"}

	if len(*thisList) != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range *thisList {
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

	var thisList *[]string
	thisList = data.(*[]string)

	arr := []string{"httpbin.org:80", "httpbin2.org:80"}

	if len(*thisList) != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range *thisList {
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

	host := data.(string)

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

	host := data.(string)

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

	var thisList *[]string
	thisList = data.(*[]string)

	arr := []string{"httpbin.org:80"}

	if len(*thisList) != len(arr) {
		t.Error("Result lists length do not match expected value")
	}

	for i, v := range *thisList {
		if v != arr[i] {
			err := "Value is wrong, should be: " + arr[i] + " have: " + v
			t.Error(err)
		}
	}

}
