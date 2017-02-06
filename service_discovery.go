package main

import (
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/lonelycode/gabs"
)

const ARRAY_NAME = "tyk_array"

type ServiceDiscovery struct {
	spec                *apidef.ServiceDiscoveryConfiguration
	isNested            bool
	isTargetList        bool
	endpointReturnsList bool
	portSeperate        bool
	dataPath            string
	parentPath          string
	portPath            string
	targetPath          string
}

func (s *ServiceDiscovery) New(spec *apidef.ServiceDiscoveryConfiguration) {
	s.spec = spec
	s.isNested = spec.UseNestedQuery
	s.isTargetList = spec.UseTargetList
	s.endpointReturnsList = spec.EndpointReturnsList
	s.targetPath = spec.TargetPath

	if spec.PortDataPath != "" {
		s.portSeperate = true
		s.portPath = spec.PortDataPath
	}

	if spec.ParentDataPath != "" {
		s.parentPath = spec.ParentDataPath
	}

	s.dataPath = spec.DataPath
}

func (s *ServiceDiscovery) getServiceData(name string) (string, error) {
	log.Debug("Getting ", name)
	resp, err := http.Get(name)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(contents), nil
}

func (s *ServiceDiscovery) decodeToNameSpace(namespace string, jsonParsed *gabs.Container) interface{} {
	log.Debug("Namespace: ", namespace)
	value := jsonParsed.Path(namespace).Data()
	return value
}

func (s *ServiceDiscovery) decodeToNameSpaceAsArray(namespace string, jsonParsed *gabs.Container) *[]*gabs.Container {
	log.Debug("Array Namespace: ", namespace)
	log.Debug("Container: ", jsonParsed)
	value, _ := jsonParsed.Path(namespace).Children()
	log.Debug("Array value:", value)
	return &value
}

func (s *ServiceDiscovery) GetPortFromObject(host *string, obj *gabs.Container) {
	if s.portSeperate {
		// Grab the port object
		port := s.decodeToNameSpace(s.portPath, obj)

		switch port.(type) {
		case []interface{}:
			port = port.([]interface{})[0]
		}

		var portToUse string
		switch port.(type) {
		case string:
			portToUse = port.(string)
		case float64:
			portToUse = strconv.Itoa(int(port.(float64)))
		}

		*host += ":" + portToUse
		log.Debug("Host: ", *host)
	}
}

func (s *ServiceDiscovery) GetNestedObject(item *gabs.Container) string {
	log.Debug("Parent Data: ", item)
	parentData := s.decodeToNameSpace(s.parentPath, item)
	// Get the data path from the decoded object
	subContainer := gabs.Container{}
	switch parentData.(type) {
	default:
		log.Debug("Get Nested Object: parentData is not a string")
		return ""
	case string:
	}
	s.ParseObject(parentData.(string), &subContainer)
	log.Debug("Parent SubContainer: ", subContainer)
	// Get the hostname
	hostnameData := s.decodeToNameSpace(s.dataPath, &subContainer)
	switch hostnameData.(type) {
	default:
		log.Debug("Get Nested Object: hostname is not a string")
		return ""
	case string:
	}
	hostname := hostnameData.(string)
	// Get the port
	s.GetPortFromObject(&hostname, &subContainer)
	return hostname
}

func (s *ServiceDiscovery) GetObject(item *gabs.Container) string {
	hostnameData := s.decodeToNameSpace(s.dataPath, item)
	switch hostnameData.(type) {
	default:
		log.Warning("Get Object: hostname is not a string")
		return ""
	case string:
	}
	hostname := hostnameData.(string)
	log.Debug("get object hostname: ", hostname)
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
	return strings.HasPrefix(val, "[")
}

func (s *ServiceDiscovery) GetSubObjectFromList(objList *gabs.Container) *[]string {
	hostList := []string{}
	var hostname string
	var set *[]*gabs.Container
	if s.endpointReturnsList {
		// pre-process the object since we've nested it
		set = s.decodeToNameSpaceAsArray(ARRAY_NAME, objList)
		log.Debug("set: ", set)
	} else {
		// It's an object, but the value may be nested
		if s.isNested {
			// Get the actual raw string object
			parentData := s.decodeToNameSpace(s.parentPath, objList)
			// Get the data path from the decoded object
			subContainer := gabs.Container{}

			switch parentData.(type) {
			default:
				log.Debug("parentData is not a string")
				return &hostList
			case string:
			}
			// Now check if this string is a list
			nestedString := parentData.(string)
			if s.isList(nestedString) {
				log.Debug("Yup, it's a list")
				s.ConvertRawListToObj(&nestedString)
				s.ParseObject(nestedString, &subContainer)
				set = s.decodeToNameSpaceAsArray(ARRAY_NAME, &subContainer)

				// Hijack this here because we need to use a non-nested get
				for _, item := range *set {
					log.Debug("Child in list: ", item)
					hostname = s.GetObject(item) + s.targetPath
					// Add to list
					hostList = append(hostList, hostname)
				}
				return &hostList
			}
			log.Debug("Not a list")
			switch parentData.(type) {
			default:
				log.Debug("parentData is not a string")
			case string:
				s.ParseObject(parentData.(string), &subContainer)
				set = s.decodeToNameSpaceAsArray(s.dataPath, objList)
				log.Debug("set (object list): ", objList)
			}
		} else if s.parentPath != "" {
			set = s.decodeToNameSpaceAsArray(s.parentPath, objList)
		}

	}

	if set != nil {
		for _, item := range *set {
			log.Debug("Child in list: ", item)
			hostname = s.GetHostname(item) + s.targetPath
			// Add to list
			hostList = append(hostList, hostname)
		}
	} else {
		log.Debug("Set is nil")
	}
	return &hostList
}

func (s *ServiceDiscovery) GetSubObject(obj *gabs.Container) string {
	var hostname string
	hostname = s.GetHostname(obj) + s.targetPath

	return hostname
}

func (s *ServiceDiscovery) ConvertRawListToObj(RawData *string) {
	// Modify to turn a list object into a regular object
	d := `{"` + ARRAY_NAME + `":` + *RawData + `}`
	*RawData = d
}

func (s *ServiceDiscovery) ParseObject(contents string, jsonParsed *gabs.Container) error {
	log.Debug("Parsing raw data: ", contents)
	jp, err := gabs.ParseJSON([]byte(contents))
	if err != nil {
		log.Error(err)
	}
	*jsonParsed = *jp
	log.Debug("Got:", jsonParsed)
	return err
}

func (s *ServiceDiscovery) ProcessRawData(rawData string) (*apidef.HostList, error) {
	var jsonParsed gabs.Container

	hostlist := apidef.NewHostList()

	if s.endpointReturnsList {
		// Convert to an object
		s.ConvertRawListToObj(&rawData)
		if err := s.ParseObject(rawData, &jsonParsed); err != nil {
			log.Error("Parse object failed: ", err)
			return nil, err
		}

		log.Debug("Parsed object list: ", jsonParsed)
		// Treat JSON as a list and then apply the data path
		if s.isTargetList {
			// Get all values
			asList := s.GetSubObjectFromList(&jsonParsed)
			log.Debug("Host list:", asList)
			hostlist.Set(*asList)
			return hostlist, nil
		}

		// Get the top value
		list := s.GetSubObjectFromList(&jsonParsed)
		var host string
		for _, v := range *list {
			host = v
			break
		}

		hostlist.Set([]string{host})
		return hostlist, nil
	}

	// It's an object
	s.ParseObject(rawData, &jsonParsed)
	if s.isTargetList {
		// It's a list object
		log.Debug("It's a target list - getting sub object from list")
		log.Debug("Passing in: ", jsonParsed)

		asList := s.GetSubObjectFromList(&jsonParsed)
		hostlist.Set(*asList)
		log.Debug("Got from object: ", hostlist)
		return hostlist, nil
	}

	// It's a single object
	host := s.GetSubObject(&jsonParsed)
	hostlist.Set([]string{host})

	return hostlist, nil
}

func (s *ServiceDiscovery) GetTarget(serviceURL string) (*apidef.HostList, error) {
	// Get the data
	rawData, err := s.getServiceData(serviceURL)
	if err != nil {
		return nil, err
	}

	return s.ProcessRawData(rawData)

}
