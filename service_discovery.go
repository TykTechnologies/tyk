package main

import (
	"encoding/json"
	"github.com/lonelycode/gabs"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

const ARRAY_NAME string = "tyk_array"

type ServiceDiscovery struct {
	spec                *APISpec
	isNested            bool
	isTargetList        bool
	endpointReturnsList bool
	portSeperate        bool
	dataPath            string
	parentPath          string
	portPath            string
}

func (s *ServiceDiscovery) New(spec *APISpec) {
	s.spec = spec
	s.isNested = spec.Proxy.ServiceDiscovery.UseNestedQuery
	s.isTargetList = spec.Proxy.ServiceDiscovery.UseTargetList
	s.endpointReturnsList = spec.Proxy.ServiceDiscovery.EndpointReturnsList
	if spec.Proxy.ServiceDiscovery.PortDataPath != "" {
		s.portSeperate = true
		s.portPath = spec.Proxy.ServiceDiscovery.PortDataPath
	}

	if spec.Proxy.ServiceDiscovery.ParentDataPath != "" {
		s.parentPath = spec.Proxy.ServiceDiscovery.ParentDataPath
	}

	s.dataPath = spec.Proxy.ServiceDiscovery.DataPath
}

func (s *ServiceDiscovery) getServiceData(name string) (string, error) {
	log.Info("Getting ", name)
	resp, err := http.Get(s.spec.Proxy.ServiceDiscovery.QueryEndpoint)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	contents, readErr := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", readErr
	}

	return string(contents), nil
}

func (s *ServiceDiscovery) decodeRawJsonString(value string) interface{} {
	var thisObj interface{}
	json.Unmarshal([]byte(value), &thisObj)
	return &thisObj
}

func (s *ServiceDiscovery) decodeToNameSpace(namespace string, jsonParsed *gabs.Container) interface{} {
	log.Info("Namespace: ", namespace)
	value := jsonParsed.Path(namespace).Data()
	return value
}

func (s *ServiceDiscovery) decodeToNameSpaceAsArray(namespace string, jsonParsed *gabs.Container) *[]*gabs.Container {
	log.Info("Array Namespace: ", namespace)
	log.Info("Container: ", jsonParsed)
	value, _ := jsonParsed.Path(namespace).Children()
	log.Info("Array value:", value)
	return &value
}

func (s *ServiceDiscovery) GetPortFromObject(host *string, obj *gabs.Container) {
	if s.portSeperate {
		// Grab the port object
		port := s.decodeToNameSpace(s.portPath, obj)
		// TODO: Add it to host

		var portToUse string
		switch port.(type) {
		case string:
			portToUse = port.(string)
		case float64:
			portToUse = strconv.Itoa(int(port.(float64)))
		}

		*host += ":" + portToUse
		log.Info("Host: ", *host)
	}
}

func (s *ServiceDiscovery) GetNestedObject(item *gabs.Container) string {
	log.Info("Parent Data: ", item)
	parentData := s.decodeToNameSpace(s.parentPath, item)
	// Get the data path from the decoded object
	subContainer := gabs.Container{}
	s.ParseObject(parentData.(string), &subContainer)
	log.Info("Parent SubContainer: ", subContainer)
	// Get the hostname
	hostname := s.decodeToNameSpace(s.dataPath, &subContainer).(string)
	// Get the port
	s.GetPortFromObject(&hostname, &subContainer)
	return hostname
}

func (s *ServiceDiscovery) GetObject(item *gabs.Container) string {
	hostname := s.decodeToNameSpace(s.dataPath, item).(string)
	// Get the port
	s.GetPortFromObject(&hostname, item)
	return hostname
}

func (s *ServiceDiscovery) GetHostname(item *gabs.Container) string {
	var hostname string
	// Get a nested object
	if s.isNested {
		hostname = s.GetNestedObject(item)
	} else {
		hostname = s.GetObject(item)
	}
	return hostname
}

func (s *ServiceDiscovery) isList(val string) bool {
	if len(val) > 0 {
		if strings.HasPrefix(val, "[") {
			return true
		}
	}
	return false
}
func (s *ServiceDiscovery) GetSubObjectFromList(objList *gabs.Container) *[]string {
	hostList := []string{}
	var hostname string
	var thisSet *[]*gabs.Container
	if s.endpointReturnsList {
		// pre-process the object since we've nested it
		thisSet = s.decodeToNameSpaceAsArray(ARRAY_NAME, objList)
		log.Info("thisSet: ", thisSet)
	} else {
		// It's an object, but the value may be nested
		if s.isNested {
			// Get the actual raw string object
			parentData := s.decodeToNameSpace(s.parentPath, objList)
			// Get the data path from the decoded object
			subContainer := gabs.Container{}
			// Now check if this string is a list
			nestedString := parentData.(string)
			if s.isList(nestedString) {
				log.Warning("Yup, it's a list")
				s.ConvertRawListToObj(&nestedString)
				s.ParseObject(nestedString, &subContainer)
				thisSet = s.decodeToNameSpaceAsArray(ARRAY_NAME, &subContainer)

				// Hijack this here because we need to use a non-nested get
				for _, item := range *thisSet {
					log.Info("Child in list: ", item)
					hostname = s.GetObject(item)
					// Add to list
					hostList = append(hostList, hostname)
				}
				return &hostList

			} else {
				log.Warning("Not a list")
				s.ParseObject(parentData.(string), &subContainer)
				thisSet = s.decodeToNameSpaceAsArray(s.dataPath, objList)
				log.Info("thisSet (object list): ", objList)
			}
		}

	}

	for _, item := range *thisSet {
		log.Info("Child in list: ", item)
		hostname = s.GetHostname(item)
		// Add to list
		hostList = append(hostList, hostname)
	}
	return &hostList
}

func (s *ServiceDiscovery) GetSubObject(obj *gabs.Container) string {
	var hostname string
	hostname = s.GetHostname(obj)

	return hostname
}

func (s *ServiceDiscovery) ConvertRawListToObj(RawData *string) {
	// Modify to turn a list object into a regular object
	d := `{"` + ARRAY_NAME + `":` + *RawData + `}`
	*RawData = d
}

func (s *ServiceDiscovery) ParseObject(contents string, jsonParsed *gabs.Container) error {
	log.Info("Parsing raw data: ", contents)
	jp, pErr := gabs.ParseJSON([]byte(contents))
	log.Error(pErr)
	*jsonParsed = *jp
	log.Info("Got:", jsonParsed)
	log.Error(pErr)
	return pErr
}

func (s *ServiceDiscovery) ProcessRawData(rawData string) (interface{}, error) {
	var jsonParsed gabs.Container

	var hostlist *[]string

	if s.endpointReturnsList {
		// Convert to an object
		s.ConvertRawListToObj(&rawData)
		s.ParseObject(rawData, &jsonParsed)
		log.Info("Parsed object list: ", jsonParsed)
		// Treat JSON as a list and then apply the data path
		if s.isTargetList {
			// Get all values
			hostlist = s.GetSubObjectFromList(&jsonParsed)
			log.Info("Host list:", hostlist)
			return hostlist, nil
		}

		// Get the top value
		list := s.GetSubObjectFromList(&jsonParsed)
		var host string
		for _, v := range *list {
			host = v
			break
		}

		return host, nil
	}

	// It's an object
	s.ParseObject(rawData, &jsonParsed)
	if s.isTargetList {
		// It's a list object
		log.Warning("It's a target list - getting sub object from list")
		log.Warning("Passing in: ", jsonParsed)
		hostlist = s.GetSubObjectFromList(&jsonParsed)
		log.Warning("Got from object: ", hostlist)
		return hostlist, nil
	}

	// It's a single object
	host := s.GetSubObject(&jsonParsed)
	return host, nil
}

func (s *ServiceDiscovery) GetTarget(serviceURL string) (interface{}, error) {
	// Get the data
	rawData, err := s.getServiceData(serviceURL)
	if err != nil {
		return nil, err
	}

	return s.ProcessRawData(rawData)

}
