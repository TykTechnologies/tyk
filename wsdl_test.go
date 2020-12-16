package main

import (
	"bytes"
	"testing"
)

type testWSDLInput struct {
	wsdlDefinition string
	isInvalidInput bool
	data           []testWSDLData
}

type testWSDLData struct {
	servicePortNameMapping map[string]string
	noOfEndpoints          int
	endpoints              []endpointData
	returnErr              bool
}

type endpointData struct {
	method       string
	path         string
	matchPattern string
	rewritePath  string
}

var testData = []testWSDLInput{
	{
		wsdlDefinition: holidayService,
		data: []testWSDLData{
			{
				servicePortNameMapping: map[string]string{"HolidayService2": "HolidayService2Soap"},
				noOfEndpoints:          6,
				endpoints: []endpointData{
					{
						path:         "HolidayService2/GetHolidaysForDateRange",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidaysForDateRange",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetCountriesAvailable",
						method:       "POST",
						matchPattern: "HolidayService2/GetCountriesAvailable",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetHolidaysAvailable",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidaysAvailable",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetHolidaysForMonth",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidaysForMonth",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetHolidaysForYear",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidaysForYear",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetHolidayDate",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidayDate",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
				},
			},
			{
				servicePortNameMapping: map[string]string{"HolidayService2": "HolidayService2HttpGet"},
				noOfEndpoints:          6,
				endpoints: []endpointData{
					{
						path:         "HolidayService2/GetHolidaysForDateRange",
						method:       "GET",
						matchPattern: "(/GetHolidaysForDateRange.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetCountriesAvailable",
						method:       "GET",
						matchPattern: "(/GetCountriesAvailable.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetHolidaysAvailable",
						method:       "GET",
						matchPattern: "(/GetHolidaysAvailable.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetHolidaysForMonth",
						method:       "GET",
						matchPattern: "(/GetHolidaysForMonth.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetHolidaysForYear",
						method:       "GET",
						matchPattern: "(/GetHolidaysForYear.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetHolidayDate",
						method:       "GET",
						matchPattern: "(/GetHolidayDate.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
				},
			},
			{
				servicePortNameMapping: map[string]string{"HolidayService2": "HolidayService2HttpPost"},
				noOfEndpoints:          6,
				endpoints: []endpointData{
					{
						path:         "HolidayService2/GetHolidaysForDateRange",
						method:       "POST",
						matchPattern: "(/GetHolidaysForDateRange.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetCountriesAvailable",
						method:       "POST",
						matchPattern: "(/GetCountriesAvailable.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetHolidaysAvailable",
						method:       "POST",
						matchPattern: "(/GetHolidaysAvailable.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetHolidaysForMonth",
						method:       "POST",
						matchPattern: "(/GetHolidaysForMonth.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetHolidaysForYear",
						method:       "POST",
						matchPattern: "(/GetHolidaysForYear.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
					{
						path:         "HolidayService2/GetHolidayDate",
						method:       "POST",
						matchPattern: "(/GetHolidayDate.*)",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx$1",
					},
				},
			},
			{
				servicePortNameMapping: map[string]string{"HolidayService2": ""},
				noOfEndpoints:          6,
				endpoints: []endpointData{
					{
						path:         "HolidayService2/GetHolidaysForDateRange",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidaysForDateRange",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetCountriesAvailable",
						method:       "POST",
						matchPattern: "HolidayService2/GetCountriesAvailable",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetHolidaysAvailable",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidaysAvailable",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetHolidaysForMonth",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidaysForMonth",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetHolidaysForYear",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidaysForYear",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
					{
						path:         "HolidayService2/GetHolidayDate",
						method:       "POST",
						matchPattern: "HolidayService2/GetHolidayDate",
						rewritePath:  "http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx",
					},
				},
			},
			{
				//invalid portName is provided
				//should throw an error
				servicePortNameMapping: map[string]string{"HolidayService2": "something"},
				returnErr:              true,
			},
		},
	},
	{
		//smtp protocol is not supported
		//should throw error
		wsdlDefinition: smtpExample,
		data: []testWSDLData{
			{
				servicePortNameMapping: map[string]string{"StockQuoteService": "StockQuotePort"},
				returnErr:              true,
			},
		},
	},
	{
		//Invalid input
		wsdlDefinition: "<ghfsdfjadhfkadf>",
		isInvalidInput: true,
	},
	{
		//Invalid input
		wsdlDefinition: wsdl_2_0_example,
		isInvalidInput: true,
	},
}

func TestToAPIDefinition_WSDL(t *testing.T) {
	for _, input := range testData {
		wsdl_imp := &WSDLDef{}
		buff := bytes.NewBufferString(input.wsdlDefinition)

		err := wsdl_imp.LoadFrom(buff)
		if err != nil {
			if input.isInvalidInput {
				continue
			} else {
				t.Fatal(err)
			}
		}

		for _, data := range input.data {
			wsdl_imp.SetServicePortMapping(data.servicePortNameMapping)
			def, err := wsdl_imp.ToAPIDefinition("testOrg", "http://test.com", false)

			if err != nil {
				if !data.returnErr {
					t.Fatal(err)
				} else {
					continue
				}
			}

			if def.VersionData.NotVersioned {
				t.Fatal("WSDL import must always be versioned")
			}

			if len(def.VersionData.Versions) > 1 {
				t.Fatal("There should only be one version")
			}

			v, ok := def.VersionData.Versions["1.0.0"]
			if !ok {
				t.Fatal("Version could not be found")
			}

			if len(v.ExtendedPaths.TrackEndpoints) != data.noOfEndpoints {
				t.Fatalf("Expected %v endpoints, found %v\n", data.noOfEndpoints, len(v.ExtendedPaths.TrackEndpoints))
			}

			for _, endpoint := range data.endpoints {
				for _, rewriteData := range v.ExtendedPaths.URLRewrite {

					if rewriteData.Path == endpoint.path {
						if rewriteData.Method != endpoint.method {
							t.Fatalf("Invalid endpoint method. Expected %s found %s", endpoint.method, rewriteData.Method)
						}

						if rewriteData.MatchPattern != endpoint.matchPattern {
							t.Fatalf("Invalid matchPattern. Expected %s found %s", endpoint.matchPattern, rewriteData.MatchPattern)
						}

						if rewriteData.RewriteTo != endpoint.rewritePath {
							t.Fatalf("Invalid rewrite path. Expected %s found %s", endpoint.rewritePath, rewriteData.RewriteTo)
						}
					}

				}
			}
		}
	}
}

var holidayService string = `
<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:mime="http://schemas.xmlsoap.org/wsdl/mime/" xmlns:tns="http://www.holidaywebservice.com/HolidayService_v2/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:s="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/" xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" targetNamespace="http://www.holidaywebservice.com/HolidayService_v2/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
  <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Web service that calculates holiday dates. (Version 2.0.1)</wsdl:documentation>
  <wsdl:types>
    <s:schema elementFormDefault="qualified" targetNamespace="http://www.holidaywebservice.com/HolidayService_v2/">
      <s:element name="GetCountriesAvailable">
        <s:complexType/>
      </s:element>
      <s:element name="GetCountriesAvailableResponse">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="0" maxOccurs="1" name="GetCountriesAvailableResult" type="tns:ArrayOfCountryCode"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:complexType name="ArrayOfCountryCode">
        <s:sequence>
          <s:element minOccurs="0" maxOccurs="unbounded" name="CountryCode" nillable="true" type="tns:CountryCode"/>
        </s:sequence>
      </s:complexType>
      <s:complexType name="CountryCode">
        <s:complexContent mixed="false">
          <s:extension base="tns:CodeDescriptionBase"/>
        </s:complexContent>
      </s:complexType>
      <s:complexType name="CodeDescriptionBase" abstract="true">
        <s:sequence>
          <s:element minOccurs="0" maxOccurs="1" name="Code" type="s:string"/>
          <s:element minOccurs="0" maxOccurs="1" name="Description" type="s:string"/>
        </s:sequence>
      </s:complexType>
      <s:element name="GetHolidaysAvailable">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="countryCode" type="tns:Country"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:simpleType name="Country">
        <s:restriction base="s:string">
          <s:enumeration value="Canada"/>
          <s:enumeration value="GreatBritain"/>
          <s:enumeration value="IrelandNorthern"/>
          <s:enumeration value="IrelandRepublicOf"/>
          <s:enumeration value="Scotland"/>
          <s:enumeration value="UnitedStates"/>
        </s:restriction>
      </s:simpleType>
      <s:element name="GetHolidaysAvailableResponse">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="0" maxOccurs="1" name="GetHolidaysAvailableResult" type="tns:ArrayOfHolidayCode"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:complexType name="ArrayOfHolidayCode">
        <s:sequence>
          <s:element minOccurs="0" maxOccurs="unbounded" name="HolidayCode" nillable="true" type="tns:HolidayCode"/>
        </s:sequence>
      </s:complexType>
      <s:complexType name="HolidayCode">
        <s:complexContent mixed="false">
          <s:extension base="tns:CodeDescriptionBase"/>
        </s:complexContent>
      </s:complexType>
      <s:element name="GetHolidayDate">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="countryCode" type="tns:Country"/>
            <s:element minOccurs="0" maxOccurs="1" name="holidayCode" type="s:string"/>
            <s:element minOccurs="1" maxOccurs="1" name="year" type="s:int"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="GetHolidayDateResponse">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="GetHolidayDateResult" type="s:dateTime"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="GetHolidaysForDateRange">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="countryCode" type="tns:Country"/>
            <s:element minOccurs="1" maxOccurs="1" name="startDate" type="s:dateTime"/>
            <s:element minOccurs="1" maxOccurs="1" name="endDate" type="s:dateTime"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="GetHolidaysForDateRangeResponse">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="0" maxOccurs="1" name="GetHolidaysForDateRangeResult" type="tns:ArrayOfHoliday"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:complexType name="ArrayOfHoliday">
        <s:sequence>
          <s:element minOccurs="0" maxOccurs="unbounded" name="Holiday" nillable="true" type="tns:Holiday"/>
        </s:sequence>
      </s:complexType>
      <s:complexType name="Holiday">
        <s:sequence>
          <s:element minOccurs="1" maxOccurs="1" name="Country" type="tns:Country"/>
          <s:element minOccurs="0" maxOccurs="1" name="HolidayCode" type="s:string"/>
          <s:element minOccurs="0" maxOccurs="1" name="Descriptor" type="s:string"/>
          <s:element minOccurs="1" maxOccurs="1" name="HolidayType" type="tns:HolidayType"/>
          <s:element minOccurs="1" maxOccurs="1" name="DateType" type="tns:HolidayDateType"/>
          <s:element minOccurs="1" maxOccurs="1" name="BankHoliday" type="tns:BankHoliday"/>
          <s:element minOccurs="1" maxOccurs="1" name="Date" type="s:dateTime"/>
          <s:element minOccurs="0" maxOccurs="1" name="RelatedHolidayCode" type="s:string"/>
          <s:element minOccurs="0" maxOccurs="1" name="ApplicableRegions" type="tns:ArrayOfRegionCode"/>
        </s:sequence>
      </s:complexType>
      <s:simpleType name="HolidayType">
        <s:restriction base="s:string">
          <s:enumeration value="Notable"/>
          <s:enumeration value="Religious"/>
          <s:enumeration value="NotableReligious"/>
          <s:enumeration value="Other"/>
        </s:restriction>
      </s:simpleType>
      <s:simpleType name="HolidayDateType">
        <s:restriction base="s:string">
          <s:enumeration value="Observed"/>
          <s:enumeration value="Actual"/>
          <s:enumeration value="ObservedActual"/>
        </s:restriction>
      </s:simpleType>
      <s:simpleType name="BankHoliday">
        <s:restriction base="s:string">
          <s:enumeration value="Recognized"/>
          <s:enumeration value="NotRecognized"/>
        </s:restriction>
      </s:simpleType>
      <s:complexType name="ArrayOfRegionCode">
        <s:sequence>
          <s:element minOccurs="0" maxOccurs="unbounded" name="RegionCode" nillable="true" type="tns:RegionCode"/>
        </s:sequence>
      </s:complexType>
      <s:complexType name="RegionCode">
        <s:complexContent mixed="false">
          <s:extension base="tns:CodeDescriptionBase"/>
        </s:complexContent>
      </s:complexType>
      <s:element name="GetHolidaysForYear">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="countryCode" type="tns:Country"/>
            <s:element minOccurs="1" maxOccurs="1" name="year" type="s:int"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="GetHolidaysForYearResponse">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="0" maxOccurs="1" name="GetHolidaysForYearResult" type="tns:ArrayOfHoliday"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="GetHolidaysForMonth">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="1" maxOccurs="1" name="countryCode" type="tns:Country"/>
            <s:element minOccurs="1" maxOccurs="1" name="year" type="s:int"/>
            <s:element minOccurs="1" maxOccurs="1" name="month" type="s:int"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="GetHolidaysForMonthResponse">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="0" maxOccurs="1" name="GetHolidaysForMonthResult" type="tns:ArrayOfHoliday"/>
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="ArrayOfCountryCode" nillable="true" type="tns:ArrayOfCountryCode"/>
      <s:element name="ArrayOfHolidayCode" nillable="true" type="tns:ArrayOfHolidayCode"/>
      <s:element name="dateTime" type="s:dateTime"/>
      <s:element name="ArrayOfHoliday" nillable="true" type="tns:ArrayOfHoliday"/>
    </s:schema>
  </wsdl:types>
  <wsdl:message name="GetCountriesAvailableSoapIn">
    <wsdl:part name="parameters" element="tns:GetCountriesAvailable"/>
  </wsdl:message>
  <wsdl:message name="GetCountriesAvailableSoapOut">
    <wsdl:part name="parameters" element="tns:GetCountriesAvailableResponse"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysAvailableSoapIn">
    <wsdl:part name="parameters" element="tns:GetHolidaysAvailable"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysAvailableSoapOut">
    <wsdl:part name="parameters" element="tns:GetHolidaysAvailableResponse"/>
  </wsdl:message>
  <wsdl:message name="GetHolidayDateSoapIn">
    <wsdl:part name="parameters" element="tns:GetHolidayDate"/>
  </wsdl:message>
  <wsdl:message name="GetHolidayDateSoapOut">
    <wsdl:part name="parameters" element="tns:GetHolidayDateResponse"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForDateRangeSoapIn">
    <wsdl:part name="parameters" element="tns:GetHolidaysForDateRange"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForDateRangeSoapOut">
    <wsdl:part name="parameters" element="tns:GetHolidaysForDateRangeResponse"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForYearSoapIn">
    <wsdl:part name="parameters" element="tns:GetHolidaysForYear"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForYearSoapOut">
    <wsdl:part name="parameters" element="tns:GetHolidaysForYearResponse"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForMonthSoapIn">
    <wsdl:part name="parameters" element="tns:GetHolidaysForMonth"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForMonthSoapOut">
    <wsdl:part name="parameters" element="tns:GetHolidaysForMonthResponse"/>
  </wsdl:message>
  <wsdl:message name="GetCountriesAvailableHttpGetIn"/>
  <wsdl:message name="GetCountriesAvailableHttpGetOut">
    <wsdl:part name="Body" element="tns:ArrayOfCountryCode"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysAvailableHttpGetIn">
    <wsdl:part name="countryCode" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysAvailableHttpGetOut">
    <wsdl:part name="Body" element="tns:ArrayOfHolidayCode"/>
  </wsdl:message>
  <wsdl:message name="GetHolidayDateHttpGetIn">
    <wsdl:part name="countryCode" type="s:string"/>
    <wsdl:part name="holidayCode" type="s:string"/>
    <wsdl:part name="year" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidayDateHttpGetOut">
    <wsdl:part name="Body" element="tns:dateTime"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForDateRangeHttpGetIn">
    <wsdl:part name="countryCode" type="s:string"/>
    <wsdl:part name="startDate" type="s:string"/>
    <wsdl:part name="endDate" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForDateRangeHttpGetOut">
    <wsdl:part name="Body" element="tns:ArrayOfHoliday"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForYearHttpGetIn">
    <wsdl:part name="countryCode" type="s:string"/>
    <wsdl:part name="year" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForYearHttpGetOut">
    <wsdl:part name="Body" element="tns:ArrayOfHoliday"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForMonthHttpGetIn">
    <wsdl:part name="countryCode" type="s:string"/>
    <wsdl:part name="year" type="s:string"/>
    <wsdl:part name="month" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForMonthHttpGetOut">
    <wsdl:part name="Body" element="tns:ArrayOfHoliday"/>
  </wsdl:message>
  <wsdl:message name="GetCountriesAvailableHttpPostIn"/>
  <wsdl:message name="GetCountriesAvailableHttpPostOut">
    <wsdl:part name="Body" element="tns:ArrayOfCountryCode"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysAvailableHttpPostIn">
    <wsdl:part name="countryCode" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysAvailableHttpPostOut">
    <wsdl:part name="Body" element="tns:ArrayOfHolidayCode"/>
  </wsdl:message>
  <wsdl:message name="GetHolidayDateHttpPostIn">
    <wsdl:part name="countryCode" type="s:string"/>
    <wsdl:part name="holidayCode" type="s:string"/>
    <wsdl:part name="year" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidayDateHttpPostOut">
    <wsdl:part name="Body" element="tns:dateTime"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForDateRangeHttpPostIn">
    <wsdl:part name="countryCode" type="s:string"/>
    <wsdl:part name="startDate" type="s:string"/>
    <wsdl:part name="endDate" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForDateRangeHttpPostOut">
    <wsdl:part name="Body" element="tns:ArrayOfHoliday"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForYearHttpPostIn">
    <wsdl:part name="countryCode" type="s:string"/>
    <wsdl:part name="year" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForYearHttpPostOut">
    <wsdl:part name="Body" element="tns:ArrayOfHoliday"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForMonthHttpPostIn">
    <wsdl:part name="countryCode" type="s:string"/>
    <wsdl:part name="year" type="s:string"/>
    <wsdl:part name="month" type="s:string"/>
  </wsdl:message>
  <wsdl:message name="GetHolidaysForMonthHttpPostOut">
    <wsdl:part name="Body" element="tns:ArrayOfHoliday"/>
  </wsdl:message>
  <wsdl:portType name="HolidayService2Soap">
    <wsdl:operation name="GetCountriesAvailable">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the available countries.</wsdl:documentation>
      <wsdl:input message="tns:GetCountriesAvailableSoapIn"/>
      <wsdl:output message="tns:GetCountriesAvailableSoapOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysAvailable">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the available holidays for a specified country.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysAvailableSoapIn"/>
      <wsdl:output message="tns:GetHolidaysAvailableSoapOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidayDate">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the date of a specific holiday.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidayDateSoapIn"/>
      <wsdl:output message="tns:GetHolidayDateSoapOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForDateRange">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the holidays for a date range.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysForDateRangeSoapIn"/>
      <wsdl:output message="tns:GetHolidaysForDateRangeSoapOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForYear">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the holidays for an entire year.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysForYearSoapIn"/>
      <wsdl:output message="tns:GetHolidaysForYearSoapOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForMonth">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the holidays for a specific month.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysForMonthSoapIn"/>
      <wsdl:output message="tns:GetHolidaysForMonthSoapOut"/>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:portType name="HolidayService2HttpGet">
    <wsdl:operation name="GetCountriesAvailable">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the available countries.</wsdl:documentation>
      <wsdl:input message="tns:GetCountriesAvailableHttpGetIn"/>
      <wsdl:output message="tns:GetCountriesAvailableHttpGetOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysAvailable">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the available holidays for a specified country.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysAvailableHttpGetIn"/>
      <wsdl:output message="tns:GetHolidaysAvailableHttpGetOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidayDate">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the date of a specific holiday.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidayDateHttpGetIn"/>
      <wsdl:output message="tns:GetHolidayDateHttpGetOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForDateRange">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the holidays for a date range.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysForDateRangeHttpGetIn"/>
      <wsdl:output message="tns:GetHolidaysForDateRangeHttpGetOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForYear">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the holidays for an entire year.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysForYearHttpGetIn"/>
      <wsdl:output message="tns:GetHolidaysForYearHttpGetOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForMonth">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the holidays for a specific month.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysForMonthHttpGetIn"/>
      <wsdl:output message="tns:GetHolidaysForMonthHttpGetOut"/>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:portType name="HolidayService2HttpPost">
    <wsdl:operation name="GetCountriesAvailable">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the available countries.</wsdl:documentation>
      <wsdl:input message="tns:GetCountriesAvailableHttpPostIn"/>
      <wsdl:output message="tns:GetCountriesAvailableHttpPostOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysAvailable">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the available holidays for a specified country.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysAvailableHttpPostIn"/>
      <wsdl:output message="tns:GetHolidaysAvailableHttpPostOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidayDate">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the date of a specific holiday.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidayDateHttpPostIn"/>
      <wsdl:output message="tns:GetHolidayDateHttpPostOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForDateRange">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the holidays for a date range.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysForDateRangeHttpPostIn"/>
      <wsdl:output message="tns:GetHolidaysForDateRangeHttpPostOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForYear">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the holidays for an entire year.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysForYearHttpPostIn"/>
      <wsdl:output message="tns:GetHolidaysForYearHttpPostOut"/>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForMonth">
      <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Get the holidays for a specific month.</wsdl:documentation>
      <wsdl:input message="tns:GetHolidaysForMonthHttpPostIn"/>
      <wsdl:output message="tns:GetHolidaysForMonthHttpPostOut"/>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="HolidayService2Soap" type="tns:HolidayService2Soap">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="GetCountriesAvailable">
      <soap:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetCountriesAvailable" style="document"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysAvailable">
      <soap:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidaysAvailable" style="document"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidayDate">
      <soap:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidayDate" style="document"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForDateRange">
      <soap:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidaysForDateRange" style="document"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForYear">
      <soap:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidaysForYear" style="document"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForMonth">
      <soap:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidaysForMonth" style="document"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:binding name="HolidayService2Soap12" type="tns:HolidayService2Soap">
    <soap12:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="GetCountriesAvailable">
      <soap12:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetCountriesAvailable" style="document"/>
      <wsdl:input>
        <soap12:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysAvailable">
      <soap12:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidaysAvailable" style="document"/>
      <wsdl:input>
        <soap12:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidayDate">
      <soap12:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidayDate" style="document"/>
      <wsdl:input>
        <soap12:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForDateRange">
      <soap12:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidaysForDateRange" style="document"/>
      <wsdl:input>
        <soap12:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForYear">
      <soap12:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidaysForYear" style="document"/>
      <wsdl:input>
        <soap12:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForMonth">
      <soap12:operation soapAction="http://www.holidaywebservice.com/HolidayService_v2/GetHolidaysForMonth" style="document"/>
      <wsdl:input>
        <soap12:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:binding name="HolidayService2HttpGet" type="tns:HolidayService2HttpGet">
    <http:binding verb="GET"/>
    <wsdl:operation name="GetCountriesAvailable">
      <http:operation location="/GetCountriesAvailable"/>
      <wsdl:input>
        <http:urlEncoded/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysAvailable">
      <http:operation location="/GetHolidaysAvailable"/>
      <wsdl:input>
        <http:urlEncoded/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidayDate">
      <http:operation location="/GetHolidayDate"/>
      <wsdl:input>
        <http:urlEncoded/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForDateRange">
      <http:operation location="/GetHolidaysForDateRange"/>
      <wsdl:input>
        <http:urlEncoded/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForYear">
      <http:operation location="/GetHolidaysForYear"/>
      <wsdl:input>
        <http:urlEncoded/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForMonth">
      <http:operation location="/GetHolidaysForMonth"/>
      <wsdl:input>
        <http:urlEncoded/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:binding name="HolidayService2HttpPost" type="tns:HolidayService2HttpPost">
    <http:binding verb="POST"/>
    <wsdl:operation name="GetCountriesAvailable">
      <http:operation location="/GetCountriesAvailable"/>
      <wsdl:input>
        <mime:content type="application/x-www-form-urlencoded"/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysAvailable">
      <http:operation location="/GetHolidaysAvailable"/>
      <wsdl:input>
        <mime:content type="application/x-www-form-urlencoded"/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidayDate">
      <http:operation location="/GetHolidayDate"/>
      <wsdl:input>
        <mime:content type="application/x-www-form-urlencoded"/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForDateRange">
      <http:operation location="/GetHolidaysForDateRange"/>
      <wsdl:input>
        <mime:content type="application/x-www-form-urlencoded"/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForYear">
      <http:operation location="/GetHolidaysForYear"/>
      <wsdl:input>
        <mime:content type="application/x-www-form-urlencoded"/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="GetHolidaysForMonth">
      <http:operation location="/GetHolidaysForMonth"/>
      <wsdl:input>
        <mime:content type="application/x-www-form-urlencoded"/>
      </wsdl:input>
      <wsdl:output>
        <mime:mimeXml part="Body"/>
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="HolidayService2">
    <wsdl:documentation xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">Web service that calculates holiday dates. (Version 2.0.1)</wsdl:documentation>
    <wsdl:port name="HolidayService2Soap" binding="tns:HolidayService2Soap">
      <soap:address location="http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx"/>
    </wsdl:port>
    <wsdl:port name="HolidayService2Soap12" binding="tns:HolidayService2Soap12">
      <soap12:address location="http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx"/>
    </wsdl:port>
    <wsdl:port name="HolidayService2HttpGet" binding="tns:HolidayService2HttpGet">
      <http:address location="http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx"/>
    </wsdl:port>
    <wsdl:port name="HolidayService2HttpPost" binding="tns:HolidayService2HttpPost">
      <http:address location="http://www.holidaywebservice.com/HolidayService_v2/HolidayService2.asmx"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>
`

var smtpExample string = `<?xml version="1.0"?>
<definitions name="StockQuote"
          targetNamespace="http://example.com/stockquote.wsdl"
          xmlns:tns="http://example.com/stockquote.wsdl"
          xmlns:xsd1="http://example.com/stockquote.xsd"
          xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
          xmlns="http://schemas.xmlsoap.org/wsdl/">

    <message name="SubscribeToQuotes">
        <part name="body" element="xsd1:SubscribeToQuotes"/>
        <part name="subscribeheader" element="xsd1:SubscriptionHeader"/>
    </message>

    <portType name="StockQuotePortType">
        <operation name="SubscribeToQuotes">
           <input message="tns:SubscribeToQuotes"/>
        </operation>
    </portType>

    <binding name="StockQuoteSoap" type="tns:StockQuotePortType">
        <soap:binding style="document" transport="http://example.com/smtp"/>
        <operation name="SubscribeToQuotes">
           <input message="tns:SubscribeToQuotes">
               <soap:body parts="body" use="literal"/>
               <soap:header message="tns:SubscribeToQuotes" part="subscribeheader" use="literal"/>
           </input>
        </operation>
    </binding>

    <service name="StockQuoteService">
        <port name="StockQuotePort" binding="tns:StockQuoteSoap">
           <soap:address location="mailto:subscribe@example.com"/>
        </port>
    </service>

    <types>
        <schema targetNamespace="http://example.com/stockquote.xsd"
               xmlns="http://www.w3.org/2000/10/XMLSchema">
           <element name="SubscribeToQuotes">
               <complexType>
                   <all>
                       <element name="tickerSymbol" type="string"/>
                   </all>
               </complexType>
           </element>
           <element name="SubscriptionHeader" type="uriReference"/>
        </schema>
    </types>
</definitions>

`

var wsdl_2_0_example = `
<?xml version = "1.0" encoding = "utf-8" ?>
<description
    xmlns = "http://www.w3.org/ns/wsdl"
    targetNamespace = "http://yoursite.com/MyService"
    xmlns:tns = "http://yoursite.com/MyService"
    xmlns:stns = "http://yoursite.com/MyService/schema"
    xmlns:wsoap = "http://www.w3.org/ns/wsdl/soap"
    xmlns:soap = "http://www.w3.org/2003/05/soap-envelope"
    xmlns:wsdlx = "http://www.w3.org/ns/wsdl-extensions">
 
    <documentation>
        This document describes my Service. You can find additional information in
        the following web page: http://yoursite.com/MyService/help.html
    </documentation>
 
    <types>
        <xs:schema
        xmlns:xs = "http://www.w3.org/2001/XMLSchema"
        targetNamespace = "http://yoursite.com/MyService/schema"
        xmlns = "http://yoursite.com/MyService/schema" >
            <xs:element name = "checkServiceStatus" type="tCheckServiceStatus" />
            <xs:complexType name = "tCheckServiceStatus" >
                <xs:sequence>
                    <xs:element name = "checkDate" type = "xs:date" />
                    <xs:element name = "serviceName" type = "xs:string" />
                </xs:sequence>
            </xs:complexType>
            <xs:element name = " checkServiceStatusResponse" type = "xs:double" />
            <xs:element name = "dataError" type = "xs:string" />
        </xs:schema>
    </types>
 
    <interface name = "myServiceInterface">
        <fault name = "dataFault" element = "stns:dataError" />
        <operation name = "checkServiceStatusOp"
            pattern = "http://www.w3.org/ns/wsdl/in-out"
            style= " http://www.w3.org/ns/wsdl/style/iri"
            wsdlx:safe = "true">
            <input messageLabel = "In" element = "stns:checkServiceStatus" />
            <output messageLabel = "Out" element = "stns:checkServiceStatusResponse"/>
            <outfault messageLabel = "Out" ref = "tns:dataFault" />
        </operation>
    </interface>
 
    <binding name = "myServiceInterfaceSOAPBinding" 
          interface = "tns:myServiceInterface"
          type = "http://www.w3.org/ns/wsdl/soap"
          wsoap:protocol = "http://www.w3.org/2003/05/soap/bindings/HTTP/">
        <operation ref = "tns:checkServiceStatusOp" 
      wsoap:mep = "http://www.w3.org/2003/05/soap/mep/soap-response"/>
        <fault ref = "tns:dataFault" 
      wsoap:code = "soap:Sender"/>
    </binding>
 
    <service name = "myService" 
       interface = "tns:myServiceInterface">
        <endpoint name = "myServiceEndpoint" 
               binding = "tns:myServiceInterfaceSOAPBinding"
               address = "http://yoursite.com/MyService"/>
    </service>
</description>
`
