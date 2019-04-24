package importer

import (
	"encoding/xml"
	"errors"
	"github.com/TykTechnologies/tyk/apidef"
	uuid "github.com/satori/go.uuid"
	"strings"
)

const (
	NS_WSDL   = "http://schemas.xmlsoap.org/wsdl/"
	NS_SOAP   = "http://schemas.xmlsoap.org/wsdl/soap/"
	NS_SOAP12 = "http://schemas.xmlsoap.org/wsdl/soap12/"
	NS_HTTP   = "http://schemas.xmlsoap.org/wsdl/http/"
)

type WSDL struct {
	Services []*WSDLService `xml:"http://schemas.xmlsoap.org/wsdl/ service"`
	Bindings []*WSDLBinding `xml:"http://schemas.xmlsoap.org/wsdl/ binding"`
}

type WSDLService struct {
	Name  string      `xml:"name,attr"`
	Ports []*WSDLPort `xml:"http://schemas.xmlsoap.org/wsdl/ port"`
}

type WSDLPort struct {
	Name    string      `xml:"name,attr"`
	Binding string      `xml:"binding,attr"`
	Address WSDLAddress `xml:"address"`
}

type WSDLAddress struct {
	Location string `xml:"location,attr"`
}

type WSDLBinding struct {
	Name                string           `xml:"name,attr"`
	Operations          []*WSDLOperation `xml:"http://schemas.xmlsoap.org/wsdl/ operation"`
	Protocol            string
	Method              string
	isSupportedProtocol bool
}

type WSDLOperation struct {
	Name             string `xml:"name,attr"`
	Endpoint         string
	IsUrlReplacement bool
}

var bindingList map[string]*WSDLBinding

func init() {
	bindingList = make(map[string]*WSDLBinding)
}

func (b *WSDLBinding) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	//Get value of name attribute
	for _, attr := range start.Attr {
		if attr.Name.Local == "name" {
			b.Name = attr.Value
			break
		}
	}

	if b.Name == "" {
		return errors.New("Binding name is empty. Malformed wsdl")
	}

	//Fetch protocol specific data
	//If soap/soap12 is used, set Method to POST
	//If http is used, get value of verb attribute
	//If any other protocol is used, then skip
	for {
		tok, err := d.Token()
		if err != nil {
			log.Error("Error will parsing wsdl file: ", err)
			return err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			{
				switch t.Name.Local {
				case "binding":
					{
						switch t.Name.Space {
						case NS_SOAP, NS_SOAP12:
							{
								isSupportedProtocol = true
								if t.Name.Space == NS_SOAP {
									b.Protocol = "soap"
								} else {
									b.Protocol = "soap12"
								}

								//Get transport protocol
								//TODO if transport protocol is different from http
								var transport string
								for _, attr := range t.Attr {
									if attr.Name.Local == "transport" {
										transport = attr.Value
										break
									}
								}
								parts := strings.Split(transport, "/")
								if parts[len(parts)-1] == "http" {
									b.Method = "POST"
								} else {
									isSupportedProtocol = false
								}

							}
						case NS_HTTP:
							{
								isSupportedProtocol = true
								b.Protocol = "http"
								for _, attr := range t.Attr {
									if attr.Name.Local == "verb" {
										b.Method = attr.Value
										break
									}
								}

							}
						default:
							{
								log.Debug("Unsupported binding protocol is used:", t.Name.Space, ":", t.Name.Local)
								isSupportedProtocol = false
								return nil
							}
						}
					}
				case "operation":
					{
						if t.Name.Space == NS_WSDL && isSupportedProtocol {
							op := new(WSDLOperation)
							if err := d.DecodeElement(op, &t); err != nil {
								return err
							}
							b.Operations = append(b.Operations, op)
						}
					}
				default:
					{
						if err := d.Skip(); err != nil {
							return err
						}
					}
				}
			}
		case xml.EndElement:
			{
				if t.Name.Space == NS_WSDL && t.Name.Local == "binding" {
					bindingList[b.Name] = b
					return nil
				}
			}
		}
	}
}

func (op *WSDLOperation) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, attr := range start.Attr {
		if attr.Name.Local == "name" {
			op.Name = attr.Value
			break
		}
	}

	if op.Name == "" {
		return errors.New("Operation name is empty. Malformed wsdl")
	}

	var protocol string

	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			{
				if t.Name.Local == "operation" {
					switch t.Name.Space {
					case NS_SOAP, NS_SOAP12:
						{
							protocol = "soap"
							break
						}
					case NS_HTTP:
						{
							protocol = "http"
							for _, attr := range t.Attr {
								if attr.Name.Local == "location" {
									op.Endpoint = attr.Value
									break
								}
							}
							break
						}
					default:
						{
							if err := d.Skip(); err != nil {
								return err
							}
						}

					}
				}

				if protocol == "http" {
					if t.Name.Local == "urlReplacement" {
						op.IsUrlReplacement = true
						endpoint := op.Endpoint
						tmp := strings.Replace(endpoint, "(", "{", -1)
						new_endpoint := strings.Replace(tmp, ")", "}", -1)

						op.Endpoint = new_endpoint

					}
				} else {
					if err := d.Skip(); err != nil {
						return err
					}
				}
			}
		case xml.EndElement:
			{
				if t.Name.Space == NS_WSDL && t.Name.Local == "operation" {
					return nil
				}
			}
		}

	}
}

func (wsdl *WSDL) ConvertToTyk(upstreamURL, orgId string, portName map[string]string) (*apidef.APIDefinition, error) {
	ad := apidef.APIDefinition{
		Name:             wsdl.Services[0].Name,
		Active:           true,
		UseKeylessAccess: true,
		OrgID:            orgId,
		APIID:            uuid.NewV4().String(),
	}

	ad.VersionDefinition.Key = "version"
	ad.VersionDefinition.Location = "header"
	ad.VersionData.Versions = make(map[string]apidef.VersionInfo)
	ad.Proxy.ListenPath = "/" + wsdl.Services[0].Name + "/"
	ad.Proxy.StripListenPath = true
	ad.Proxy.TargetURL = upstreamURL
	versionData, err := wsdl.ConvertIntoApiVersion(portName)
	if err != nil {
		return nil, err
	}

	wsdl.InsertIntoAPIDefinitionAsVersion(versionData, &ad, "1.0.0")
	ad.VersionData.DefaultVersion = "1.0.0"
	return &ad, nil
}

func trimNamespace(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) == 1 {
		return parts[0]
	} else {
		return parts[1]
	}
}

func (wsdl *WSDL) ConvertIntoApiVersion(servicePortNames map[string]string) (apidef.VersionInfo, error) {
	versionInfo := apidef.VersionInfo{}
	versionInfo.UseExtendedPaths = true
	versionInfo.Name = "1.0.0"
	versionInfo.ExtendedPaths.TrackEndpoints = make([]apidef.TrackEndpointMeta, 0)
	versionInfo.ExtendedPaths.URLRewrite = make([]apidef.URLRewriteMeta, 0)
	versionInfo.ExtendedPaths.Internal = make([]apidef.InternalMeta, 0)

	var foundPort bool
	var serviceCount int

	for _, service := range wsdl.Services {
		foundPort = false
		if service.Name == "" {
			continue
		}
		for _, port := range service.Ports {
			portName := servicePortNames[service.Name]
			if portName == "" {
				portName = service.Ports[0].Name
			}
			if port.Name == portName {
				foundPort = true

				bindingName := trimNamespace(port.Binding)

				binding := bindingList[bindingName]
				if binding == nil {
					log.Debugf("Binding for port %s of service %s not found. Termination processing of the service", port.Name, service.Name)

					foundPort = false
					break
				}

				if !binding.isSupportedProtocol {
					log.Debug("Unsupported transport protocol. Skipping process of the service ", service.Name)
					foundPort = false
					break
				}

				if len(binding.Operations) == 0 {
					log.Debugf("No operation found for binding %s of service %s\n", binding.Name, service.Name)
					break
				}

				serviceCount++
				method := binding.Method

				//Create endpoints for each operation
				for _, op := range binding.Operations {
					operationTrackEndpoint := apidef.TrackEndpointMeta{}
					operationUrlRewrite := apidef.URLRewriteMeta{}
					path := ""

					if binding.Protocol == "http" {
						if op.Endpoint[0] == '/' {
							path = service.Name + op.Endpoint
						} else {
							path = service.Name + "/" + op.Endpoint
						}
					} else {
						path = service.Name + "/" + op.Name
					}

					//Add each operation in trackendpoint
					operationTrackEndpoint.Path = path
					operationTrackEndpoint.Method = method

					versionInfo.ExtendedPaths.TrackEndpoints = append(versionInfo.ExtendedPaths.TrackEndpoints, operationTrackEndpoint)

					//Rewrite operation to service endpoint
					operationUrlRewrite.Method = method
					operationUrlRewrite.Path = path

					if binding.Protocol == "http" {
						if op.IsUrlReplacement == true {
							pattern := ReplaceWildCards(op.Endpoint)
							operationUrlRewrite.MatchPattern = "(" + pattern + ")"
						} else {
							operationUrlRewrite.MatchPattern = "(" + op.Endpoint + ".*)"
						}
						operationUrlRewrite.RewriteTo = port.Address.Location + "$1"
					} else {
						operationUrlRewrite.MatchPattern = path
						operationUrlRewrite.RewriteTo = port.Address.Location
					}

					versionInfo.ExtendedPaths.URLRewrite = append(versionInfo.ExtendedPaths.URLRewrite, operationUrlRewrite)
				}

				break
			}
		}

		if foundPort == false {
			log.Errorf("Port for service %s not found. Skiping processing of the service", service.Name)
		}
	}

	if serviceCount == 0 {
		return versionInfo, errors.New("Error process wsdl file")
	}

	return versionInfo, nil
}

func (wsdl *WSDL) InsertIntoAPIDefinitionAsVersion(version apidef.VersionInfo, def *apidef.APIDefinition, versionName string) error {
	def.VersionData.NotVersioned = false
	def.VersionData.Versions[versionName] = version
	return nil
}

func ReplaceWildCards(endpoint string) string {
	var result []rune
	var inside bool

	for _, s := range endpoint {
		if s == '{' {
			inside = true
			continue
		} else if s == '}' {
			inside = false
			result = append(result, '.', '*')
			continue
		}

		if inside == false {
			result = append(result, s)
		}
	}
	return string(result)
}
