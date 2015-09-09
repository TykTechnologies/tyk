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
	}
	return ""
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
