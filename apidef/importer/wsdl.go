package importer

import (
	"encoding/xml"
	"errors"
	"fmt"
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
}

type WSDLOperation struct {
	Name string `xml:"name,attr"`
	Meta OperationMeta
}

type OperationMeta struct {
	SoapAction string
	Endpoint   string
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
						fmt.Print("Found binding elementi of ")
						switch t.Name.Space {
						case NS_SOAP, NS_SOAP12:
							{
								fmt.Println("soap/sopa12 protocol")
								if t.Name.Space == NS_SOAP {
									b.Protocol = "soap"
								} else {
									b.Protocol = "soap12"
								}

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
								return nil
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
							fmt.Println("Unsupported protocol. Skipping")
							return nil
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
