package gateway

import (
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/Jeffail/gabs/v2"

	"github.com/TykTechnologies/tyk/apidef"
)

const arrayName = "tyk_array"

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
	gw                  *Gateway // Added for HTTP client factory access
}

func (s *ServiceDiscovery) Init(spec *apidef.ServiceDiscoveryConfiguration, gw *Gateway) {
	s.spec = spec
	s.gw = gw
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

	// Try to use HTTP client factory for discovery service
	var resp *http.Response
	var err error

	if s.gw != nil {
		clientFactory := NewExternalHTTPClientFactory(s.gw)
		if client, clientErr := clientFactory.CreateClient("discovery"); clientErr == nil {
			log.Debugf("[ExternalServices] Using external services discovery client for URL: %s", name)
			resp, err = client.Get(name)
		} else {
			// Check if mTLS is explicitly enabled and error is certificate-related - if so, don't fallback as it would bypass security
			gwConfig := s.gw.GetConfig()
			if gwConfig.ExternalServices.Discovery.MTLS.Enabled && isMTLSError(clientErr) {
				log.WithError(clientErr).Error("mTLS configuration failed for service discovery. Discovery request will fail to maintain security.")
				// Return the TLS configuration error directly
				return "", clientErr
			} else {
				// For other errors (not configured, proxy config), fallback to default client
				log.WithError(clientErr).Debug("Failed to create discovery HTTP client, falling back to default")
				log.Debug("[ExternalServices] Falling back to legacy discovery client due to factory error")
				resp, err = http.Get(name)
			}
		}
	} else {
		// Fallback to default client if gateway not set
		log.Debug("[ExternalServices] Using default HTTP client for discovery (no gateway context)")
		resp, err = http.Get(name)
	}

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

func (s *ServiceDiscovery) decodeToNameSpaceAsArray(namespace string, jsonParsed *gabs.Container) []*gabs.Container {
	log.Debug("Array Namespace: ", namespace)
	log.Debug("Container: ", jsonParsed)
	value := jsonParsed.Path(namespace).Children()
	log.Debug("Array value:", value)
	return value
}

func (s *ServiceDiscovery) addPortFromObject(host string, obj *gabs.Container) string {
	if !s.portSeperate {
		return host
	}
	// Grab the port object
	port := s.decodeToNameSpace(s.portPath, obj)

	switch x := port.(type) {
	case []interface{}:
		port = x[0]
	}

	var portToUse string
	switch x := port.(type) {
	case string:
		portToUse = x
	case float64:
		portToUse = strconv.Itoa(int(x))
	}

	return host + ":" + portToUse
}

func (s *ServiceDiscovery) NestedObject(item *gabs.Container) string {
	parentData := s.decodeToNameSpace(s.parentPath, item)
	// Get the data path from the decoded object
	subContainer := gabs.Container{}
	switch x := parentData.(type) {
	case string:
		s.ParseObject(x, &subContainer)
	default:
		log.Debug("Get Nested Object: parentData is not a string")
		return ""
	}
	return s.Object(&subContainer)
}

func (s *ServiceDiscovery) Object(item *gabs.Container) string {
	hostnameData := s.decodeToNameSpace(s.dataPath, item)
	if str, ok := hostnameData.(string); ok {
		// Get the port
		str = s.addPortFromObject(str, item)
		return str
	}
	log.Warning("Get Object: hostname is not a string")
	return ""
}

func (s *ServiceDiscovery) Hostname(item *gabs.Container) string {
	var hostname string
	// Get a nested object
	if s.isNested {
		hostname = s.NestedObject(item)
	} else {
		hostname = s.Object(item)
	}
	return hostname
}

func (s *ServiceDiscovery) isList(val string) bool {
	return strings.HasPrefix(val, "[")
}

func (s *ServiceDiscovery) SubObjectFromList(objList *gabs.Container) []string {
	hostList := []string{}
	var hostname string
	var set []*gabs.Container
	if s.endpointReturnsList {
		// pre-process the object since we've nested it
		set = s.decodeToNameSpaceAsArray(arrayName, objList)
		log.Debug("set: ", set)
	} else if s.isNested { // It's an object, but the value may be nested
		// Get the actual raw string object
		parentData := s.decodeToNameSpace(s.parentPath, objList)
		// Get the data path from the decoded object
		subContainer := gabs.Container{}

		// Now check if this string is a list
		nestedString, ok := parentData.(string)
		if !ok {
			log.Debug("parentData is not a string")
			return hostList
		}
		if s.isList(nestedString) {
			log.Debug("Yup, it's a list")
			jsonData := s.rawListToObj(nestedString)
			s.ParseObject(jsonData, &subContainer)
			set = s.decodeToNameSpaceAsArray(arrayName, &subContainer)

			// Hijack this here because we need to use a non-nested get
			for _, item := range set {
				log.Debug("Child in list: ", item)
				hostname = s.Object(item) + s.targetPath
				// Add to list
				hostList = append(hostList, hostname)
			}
			return hostList
		}
		log.Debug("Not a list")
		s.ParseObject(nestedString, &subContainer)
		set = s.decodeToNameSpaceAsArray(s.dataPath, objList)
		log.Debug("set (object list): ", objList)
	} else if s.parentPath != "" {
		set = s.decodeToNameSpaceAsArray(s.parentPath, objList)
	}

	for _, item := range set {
		log.Debug("Child in list: ", item)
		hostname = s.Hostname(item) + s.targetPath
		// Add to list
		hostList = append(hostList, hostname)
	}
	return hostList
}

func (s *ServiceDiscovery) SubObject(obj *gabs.Container) string {
	return s.Hostname(obj) + s.targetPath
}

func (s *ServiceDiscovery) rawListToObj(rawData string) string {
	// Modify to turn a list object into a regular object
	return `{"` + arrayName + `":` + rawData + `}`
}

func (s *ServiceDiscovery) ParseObject(contents string, jsonParsed *gabs.Container) error {
	log.Debug("Parsing raw data: ", contents)
	jp, err := gabs.ParseJSON([]byte(contents))
	if err != nil {
		log.Error(err)
		return err
	}
	*jsonParsed = *jp
	log.Debug("Got:", jsonParsed)
	return nil
}

func (s *ServiceDiscovery) ProcessRawData(rawData string) (*apidef.HostList, error) {
	var jsonParsed gabs.Container

	hostlist := apidef.NewHostList()

	if s.endpointReturnsList {
		// Convert to an object
		jsonData := s.rawListToObj(rawData)
		if err := s.ParseObject(jsonData, &jsonParsed); err != nil {
			log.Error("Parse object failed: ", err)
			return nil, err
		}

		log.Debug("Parsed object list: ", jsonParsed)
		// Treat JSON as a list and then apply the data path
		if s.isTargetList {
			// Get all values
			asList := s.SubObjectFromList(&jsonParsed)
			log.Debug("Host list:", asList)
			hostlist.Set(asList)
			return hostlist, nil
		}

		// Get the top value
		list := s.SubObjectFromList(&jsonParsed)
		var host string
		for _, v := range list {
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

		asList := s.SubObjectFromList(&jsonParsed)
		hostlist.Set(asList)
		log.Debug("Got from object: ", hostlist)
		return hostlist, nil
	}

	// It's a single object
	host := s.SubObject(&jsonParsed)
	hostlist.Set([]string{host})

	return hostlist, nil
}

func (s *ServiceDiscovery) Target(serviceURL string) (*apidef.HostList, error) {
	// Get the data
	rawData, err := s.getServiceData(serviceURL)
	if err != nil {
		return nil, err
	}

	return s.ProcessRawData(rawData)

}
