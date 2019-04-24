package importer

import (
	"encoding/xml"
	"errors"
	"fmt"
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
	Name       string           `xml:"name,attr"`
	Operations []*WSDLOperation `xml:"http://schemas.xmlsoap.org/wsdl/ operation"`
	Protocol   string
	Method     string
	isProcess  bool
}

type WSDLOperation struct {
	Name string `xml:"name,attr"`
	Meta OperationMeta
}

type OperationMeta struct {
	SoapAction string
	Endpoint   string
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

	fmt.Println("Parsing binding:", b.Name)

	//Fetch protocol specific data
	//If soap/soap12 is used, set Method to POST
	//If http is used, get value of verb attribute
	//If any other protocol is used, then skip
	for {
		tok, err := d.Token()
		if err != nil {
			fmt.Println("d.Token returned err")
			return err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			{
				fmt.Println("Found startElement")
				switch t.Name.Local {
				case "binding":
					{
						fmt.Print("Found binding element of ")
						switch t.Name.Space {
						case NS_SOAP, NS_SOAP12:
							{
								fmt.Println("soap/sopa12 protocol")
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
								}
							}
						case NS_HTTP:
							{
								fmt.Println("http protocol")
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
								//Unsportted binding protocol is used
								fmt.Println("Unsupported binding protocol is used:", t.Name.Space, ":", t.Name.Local)

								d.Skip()
								return errors.New("Unsupported binding protocol is used")
							}
						}
					}
				case "operation":
					{
						if t.Name.Space == NS_WSDL && b.Method != "" {
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
				fmt.Println("Found endElement")
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

	fmt.Println("Parsing operation", op.Name)

	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			{
				fmt.Println("Found startElement")
				if t.Name.Local == "operation" {
					switch t.Name.Space {
					case NS_SOAP, NS_SOAP12:
						{
							for _, attr := range t.Attr {
								if attr.Name.Local == "soapAction" {
									op.Meta.SoapAction = attr.Value
									break
								}
							}
						}
					case NS_HTTP:
						{
							for _, attr := range t.Attr {
								if attr.Name.Local == "location" {
									op.Meta.Endpoint = attr.Value
									break
								}
							}
						}
					default:
						{
							d.Skip()
							return errors.New("Unsupported protocol is used")
						}
					}

				} else {
					if err := d.Skip(); err != nil {
						return err
					}
				}
			}
		case xml.EndElement:
			{
				fmt.Println("Found EndElement")

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

				serviceURLRewriteMeta := apidef.URLRewriteMeta{}
				serviceInternalMeta := apidef.InternalMeta{}

				fmt.Println("bindingList=", bindingList)
				fmt.Println("Access method of ", port.Binding)

				bindingName := trimNamespace(port.Binding)

				binding := bindingList[bindingName]
				if binding == nil {
					fmt.Printf("Binding for port %s of service %s not found\n", port.Name, service.Name)
					fmt.Println("Skiping processing of the service")
					foundPort = false
					break
				}
				method := binding.Method

				if method == "" {
					fmt.Println("Unsupported transport protocol. Skipping process of the service ", service.Name)
					foundPort = false
					break
				}

				if len(binding.Operations) == 0 {
					fmt.Printf("No operation found for binding %s of service %s\n", binding.Name, service.Name)
					break
				}

				serviceCount++

				// Create internal endpoint for each service
				serviceEndpointPath := service.Name + "Internal"
				serviceInternalMeta.Path = serviceEndpointPath
				serviceInternalMeta.Method = method

				versionInfo.ExtendedPaths.Internal = append(versionInfo.ExtendedPaths.Internal, serviceInternalMeta)

				//Rewrite from service endpoint to upstream
				serviceURLRewriteMeta.Method = method
				serviceURLRewriteMeta.Path = serviceEndpointPath
				serviceURLRewriteMeta.MatchPattern = serviceEndpointPath
				serviceURLRewriteMeta.RewriteTo = port.Address.Location

				versionInfo.ExtendedPaths.URLRewrite = append(versionInfo.ExtendedPaths.URLRewrite, serviceURLRewriteMeta)

				//Create endpoints for each operation
				for _, op := range binding.Operations {
					operationTrackEndpoint := apidef.TrackEndpointMeta{}
					operationUrlRewrite := apidef.URLRewriteMeta{}

					//Add each operation in trackendpoint
					operationTrackEndpoint.Path = op.Name
					operationTrackEndpoint.Method = method

					versionInfo.ExtendedPaths.TrackEndpoints = append(versionInfo.ExtendedPaths.TrackEndpoints, operationTrackEndpoint)

					//Rewrite operation to service endpoint
					operationUrlRewrite.Method = method
					operationUrlRewrite.Path = op.Name
					operationUrlRewrite.MatchPattern = op.Name
					operationUrlRewrite.RewriteTo = "tyk://self/" + serviceEndpointPath

					versionInfo.ExtendedPaths.URLRewrite = append(versionInfo.ExtendedPaths.URLRewrite, operationUrlRewrite)
				}

			}
		}
		if foundPort == false {
			fmt.Printf("Port for service %s not found. Skiping processing of the service", service.Name)

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
