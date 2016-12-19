// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP client functions.
package ldap

import (
	"fmt"
	"github.com/mavricknz/asn1-ber"
)

const (
	ControlTypeMatchedValuesRequest    = "1.2.826.0.1.3344810.2.3"
	ControlTypePermissiveModifyRequest = "1.2.840.113556.1.4.1413"
	ControlTypePaging                  = "1.2.840.113556.1.4.319"
	ControlTypeManageDsaITRequest      = "2.16.840.1.113730.3.4.2"
	ControlTypeSubtreeDeleteRequest    = "1.2.840.113556.1.4.805"
	ControlTypeNoOpRequest             = "1.3.6.1.4.1.4203.1.10.2"
	ControlTypeServerSideSortRequest   = "1.2.840.113556.1.4.473"
	ControlTypeServerSideSortResponse  = "1.2.840.113556.1.4.474"
	ControlTypeVlvRequest              = "2.16.840.1.113730.3.4.9"
	ControlTypeVlvResponse             = "2.16.840.1.113730.3.4.10"

//1.2.840.113556.1.4.473
//1.3.6.1.1.12
//1.3.6.1.1.13.1
//1.3.6.1.1.13.2
//1.3.6.1.4.1.26027.1.5.2
//1.3.6.1.4.1.42.2.27.8.5.1
//1.3.6.1.4.1.42.2.27.9.5.2
//1.3.6.1.4.1.42.2.27.9.5.8
//1.3.6.1.4.1.4203.1.10.1
//1.3.6.1.4.1.7628.5.101.1
//2.16.840.1.113730.3.4.12
//2.16.840.1.113730.3.4.16
//2.16.840.1.113730.3.4.17
//2.16.840.1.113730.3.4.18
//2.16.840.1.113730.3.4.19
//2.16.840.1.113730.3.4.3
//2.16.840.1.113730.3.4.4
//2.16.840.1.113730.3.4.5
//
)

var ControlTypeMap = map[string]string{
	ControlTypeMatchedValuesRequest:    "MatchedValuesRequest",
	ControlTypePermissiveModifyRequest: "PermissiveModifyRequest",
	ControlTypePaging:                  "Paging",
	ControlTypeManageDsaITRequest:      "ManageDsaITRequest",
	ControlTypeSubtreeDeleteRequest:    "SubtreeDeleteRequest",
	ControlTypeNoOpRequest:             "NoOpRequest",
	ControlTypeServerSideSortRequest:   "ServerSideSortRequest",
	ControlTypeServerSideSortResponse:  "ServerSideSortResponse",
	ControlTypeVlvRequest:              "VlvRequest",
	ControlTypeVlvResponse:             "VlvResponse",
}

var ControlDecodeMap = map[string]func(p *ber.Packet) (Control, error){
	ControlTypeServerSideSortResponse: NewControlServerSideSortResponse,
	ControlTypePaging:                 NewControlPagingFromPacket,
	ControlTypeVlvResponse:            NewControlVlvResponse,
}

// Control Interface
type Control interface {
	Encode() (*ber.Packet, error)
	GetControlType() string
	String() string
}

type ControlString struct {
	ControlType  string
	Criticality  bool
	ControlValue string
}

func NewControlStringFromPacket(p *ber.Packet) (Control, error) {
	controlType, criticality, value := decodeControlTypeAndCrit(p)
	c := new(ControlString)
	c.ControlType = controlType
	c.Criticality = criticality
	c.ControlValue = value.ValueString()
	return c, nil
}

func (c *ControlString) GetControlType() string {
	return c.ControlType
}

func (c *ControlString) Encode() (p *ber.Packet, err error) {
	p = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, c.ControlType, "Control Type ("+ControlTypeMap[c.ControlType]+")"))
	if c.Criticality {
		p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimative, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	if len(c.ControlValue) != 0 {
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, c.ControlValue, "Control Value"))
	}
	return p, nil
}

func (c *ControlString) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %t  Control Value: %s", ControlTypeMap[c.ControlType], c.ControlType, c.Criticality, c.ControlValue)
}

type ControlPaging struct {
	PagingSize uint32
	Cookie     []byte
}

func NewControlPaging(PagingSize uint32) *ControlPaging {
	return &ControlPaging{PagingSize: PagingSize}
}

func NewControlPagingFromPacket(p *ber.Packet) (Control, error) {
	_, _, value := decodeControlTypeAndCrit(p)
	value.Description += " (Paging)"
	c := new(ControlPaging)

	if value.Value != nil {
		value_children := ber.DecodePacket(value.Data.Bytes())
		value.Data.Truncate(0)
		value.Value = nil
		value.AppendChild(value_children)
	}
	value = value.Children[0]
	value.Description = "Search Control Value"
	value.Children[0].Description = "Paging Size"
	value.Children[1].Description = "Cookie"
	c.PagingSize = uint32(value.Children[0].Value.(uint64))
	c.Cookie = value.Children[1].Data.Bytes()
	value.Children[1].Value = c.Cookie
	return c, nil
}

func (c *ControlPaging) GetControlType() string {
	return ControlTypePaging
}

func (c *ControlPaging) Encode() (p *ber.Packet, err error) {
	p = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, ControlTypePaging, "Control Type ("+ControlTypeMap[ControlTypePaging]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, nil, "Control Value (Paging)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(c.PagingSize), "Paging Size"))
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)

	p.AppendChild(p2)
	return p, nil
}

func (c *ControlPaging) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  PagingSize: %d  Cookie: %q",
		ControlTypeMap[ControlTypePaging],
		ControlTypePaging,
		false,
		c.PagingSize,
		c.Cookie)
}

func (c *ControlPaging) SetCookie(Cookie []byte) {
	c.Cookie = Cookie
}

func FindControl(controls []Control, controlType string) (position int, control Control) {
	for pos, c := range controls {
		if c.GetControlType() == controlType {
			return pos, c
		}
	}
	return -1, nil
}

func ReplaceControl(controls []Control, control Control) (oldControl Control) {
	ControlType := control.GetControlType()
	pos, c := FindControl(controls, ControlType)
	if c != nil {
		controls[pos] = control
		return c
	}
	controls = append(controls, control)
	return control
}

///*
//Control ::= SEQUENCE {
//             controlType             LDAPOID,
//             criticality             BOOLEAN DEFAULT FALSE,
//             controlValue            OCTET STRING OPTIONAL }
//*/
//// DecodeControl - Decode Response controls.
//func DecodeControl(p *ber.Packet) Control {
//	controlType, criticality, value := decodeControlTypeAndCrit(p)

//	/* Special cases */
//	switch controlType {
//	case ControlTypePaging:
//		value.Description += " (Paging)"
//		c := new(ControlPaging)
//		if value.Value != nil {
//			value_children := ber.DecodePacket(value.Data.Bytes())
//			value.Data.Truncate(0)
//			value.Value = nil
//			value.AppendChild(value_children)
//		}
//		value = value.Children[0]
//		value.Description = "Search Control Value"
//		value.Children[0].Description = "Paging Size"
//		value.Children[1].Description = "Cookie"
//		c.PagingSize = uint32(value.Children[0].Value.(uint64))
//		c.Cookie = value.Children[1].Data.Bytes()
//		value.Children[1].Value = c.Cookie
//		return c
//	}
//	c := new(ControlString)
//	c.ControlType = controlType
//	c.Criticality = criticality
//	c.ControlValue = value.ValueString()
//	return c
//}

func decodeControlTypeAndCrit(p *ber.Packet) (controlType string, criticality bool, value *ber.Packet) {
	controlType = p.Children[0].ValueString()
	p.Children[0].Description = "Control Type (" + ControlTypeMap[controlType] + ")"
	criticality = false
	if len(p.Children) == 3 {
		criticality = p.Children[1].Value.(bool)
		p.Children[1].Description = "Criticality"
		value = p.Children[2]
	} else {
		value = p.Children[1]
	}
	value.Description = "Control Value"
	return
}

func NewControlString(ControlType string, Criticality bool, ControlValue string) *ControlString {
	return &ControlString{
		ControlType:  ControlType,
		Criticality:  Criticality,
		ControlValue: ControlValue,
	}
}

func encodeControls(Controls []Control) (*ber.Packet, error) {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range Controls {
		pack, err := control.Encode()
		if err != nil {
			return nil, err
		}
		p.AppendChild(pack)
	}
	return p, nil
}

/************************/
/* MatchedValuesRequest */
/************************/

func NewControlPermissiveModifyRequest(criticality bool) *ControlString {
	return NewControlString(ControlTypePermissiveModifyRequest, criticality, "")
}

/***************/
/* ManageDsaITRequest */
/***************/

func NewControlManageDsaITRequest(criticality bool) *ControlString {
	return NewControlString(ControlTypeManageDsaITRequest, criticality, "")
}

/************************/
/* SubtreeDeleteRequest */
/************************/

func NewControlSubtreeDeleteRequest(criticality bool) *ControlString {
	return NewControlString(ControlTypeSubtreeDeleteRequest, criticality, "")
}

/***************/
/* NoOpRequest */
/***************/

func NewControlNoOpRequest() *ControlString {
	return NewControlString(ControlTypeNoOpRequest, true, "")
}

/************************/
/* MatchedValuesRequest */
/************************/

type ControlMatchedValuesRequest struct {
	Criticality bool
	Filter      string
}

func NewControlMatchedValuesRequest(criticality bool, filter string) *ControlMatchedValuesRequest {
	return &ControlMatchedValuesRequest{criticality, filter}
}

func (c *ControlMatchedValuesRequest) Decode(p *ber.Packet) (*Control, error) {
	return nil, NewLDAPError(ErrorDecoding, "Decode of Control unsupported.")
}

func (c *ControlMatchedValuesRequest) GetControlType() string {
	return ControlTypeMatchedValuesRequest
}

func (c *ControlMatchedValuesRequest) Encode() (p *ber.Packet, err error) {
	p = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ControlMatchedValuesRequest")
	p.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimative,
			ber.TagOctetString, ControlTypeMatchedValuesRequest,
			"Control Type ("+ControlTypeMap[ControlTypeMatchedValuesRequest]+")"))
	if c.Criticality {
		p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimative, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	octetString := ber.Encode(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, nil, "Octet String")
	simpleFilterSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SimpleFilterItem")
	filterPacket, err := filterParse(c.Filter)
	if err != nil {
		return nil, err
	}
	simpleFilterSeq.AppendChild(filterPacket)
	octetString.AppendChild(simpleFilterSeq)
	p.AppendChild(octetString)
	return p, nil
}

func (c *ControlMatchedValuesRequest) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Filter: %s",
		ControlTypeMap[ControlTypeMatchedValuesRequest],
		ControlTypeMatchedValuesRequest,
		c.Criticality,
		c.Filter,
	)
}

/*************************/
/* ServerSideSortRequest */
/*************************/

/*
SortKeyList ::= SEQUENCE OF SEQUENCE {
                 attributeType   AttributeDescription,
                 orderingRule    [0] MatchingRuleId OPTIONAL,
                 reverseOrder    [1] BOOLEAN DEFAULT FALSE }

*/

type ServerSideSortAttrRuleOrder struct {
	AttributeName string
	OrderingRule  string
	ReverseOrder  bool
}

type ControlServerSideSortRequest struct {
	SortKeyList []ServerSideSortAttrRuleOrder
	Criticality bool
}

func NewControlServerSideSortRequest(sortKeyList []ServerSideSortAttrRuleOrder, criticality bool) *ControlServerSideSortRequest {
	return &ControlServerSideSortRequest{sortKeyList, criticality}
}

func (c *ControlServerSideSortRequest) Decode(p *ber.Packet) (*Control, error) {
	return nil, NewLDAPError(ErrorDecoding, "Decode of Control unsupported.")
}

func (c *ControlServerSideSortRequest) GetControlType() string {
	return ControlTypeServerSideSortRequest
}

func (c *ControlServerSideSortRequest) Encode() (p *ber.Packet, err error) {
	p = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ControlServerSideSortRequest")
	p.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimative,
			ber.TagOctetString, ControlTypeServerSideSortRequest,
			"Control Type ("+ControlTypeMap[ControlTypeServerSideSortRequest]+")"))
	if c.Criticality {
		p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimative, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	octetString := ber.Encode(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, nil, "Octet String")
	seqSortKeyLists := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SortKeyLists")

	for _, sortKey := range c.SortKeyList {
		seqKey := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SortKey")
		seqKey.AppendChild(
			ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, sortKey.AttributeName, "AttributeDescription"),
		)
		if len(sortKey.OrderingRule) > 0 {
			seqKey.AppendChild(
				ber.NewString(ber.ClassUniversal, ber.TypePrimative, 0, sortKey.OrderingRule, "OrderingRule"),
			)
		}
		seqKey.AppendChild(
			ber.NewBoolean(ber.ClassUniversal, ber.TypePrimative, 1, sortKey.ReverseOrder, "ReverseOrder"),
		)
		seqSortKeyLists.AppendChild(seqKey)
	}
	octetString.AppendChild(seqSortKeyLists)
	p.AppendChild(octetString)
	return p, nil
}

func (c *ControlServerSideSortRequest) String() string {
	ctext := fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t, SortKeys: ",
		ControlTypeMap[ControlTypeServerSideSortRequest],
		ControlTypeServerSideSortRequest,
		c.Criticality,
	)
	for _, sortKey := range c.SortKeyList {
		ctext += fmt.Sprintf("[%s,%s,%t]", sortKey.AttributeName, sortKey.OrderingRule, sortKey.ReverseOrder)
	}
	return ctext
}

/*************************/
/* VlvRequest */
/*************************/

var VlvDebug bool

type VlvOffSet struct {
	Offset       int32
	ContentCount int32
}

/*
  VirtualListViewRequest ::= SEQUENCE {
       beforeCount    INTEGER (0..maxInt),
       afterCount     INTEGER (0..maxInt),
       target       CHOICE {
                      byOffset        [0] SEQUENCE {
                           offset          INTEGER (1 .. maxInt),
                           contentCount    INTEGER (0 .. maxInt) },
                      greaterThanOrEqual [1] AssertionValue },
       contextID     OCTET STRING OPTIONAL }
*/
type ControlVlvRequest struct {
	Criticality        bool
	BeforeCount        int32
	AfterCount         int32
	ByOffset           *VlvOffSet
	GreaterThanOrEqual string
	ContextID          []byte
}

func (c *ControlVlvRequest) Encode() (*ber.Packet, error) {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ControlVlvRequest")
	p.AppendChild(
		ber.NewString(ber.ClassUniversal, ber.TypePrimative,
			ber.TagOctetString, ControlTypeVlvRequest,
			"Control Type ("+ControlTypeMap[ControlTypeVlvRequest]+")"))
	if c.Criticality {
		p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimative, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	octetString := ber.Encode(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, nil, "Octet String")

	vlvSeq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "VirtualListViewRequest")
	beforeCount := ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(c.BeforeCount), "BeforeCount")
	afterCount := ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(c.AfterCount), "AfterCount")
	var target *ber.Packet
	switch {
	case c.ByOffset != nil:
		target = ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "ByOffset")
		offset := ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(c.ByOffset.Offset), "Offset")
		contentCount := ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(c.ByOffset.ContentCount), "ContentCount")
		target.AppendChild(offset)
		target.AppendChild(contentCount)
	case len(c.GreaterThanOrEqual) > 0:
		// TODO incorrect for some values, binary?
		target = ber.NewString(ber.ClassContext, ber.TypePrimative, 1, c.GreaterThanOrEqual, "GreaterThanOrEqual")
	}
	if target == nil {
		return nil, NewLDAPError(ErrorEncoding, "VLV target equal to nil")
	}
	vlvSeq.AppendChild(beforeCount)
	vlvSeq.AppendChild(afterCount)
	vlvSeq.AppendChild(target)

	if len(c.ContextID) > 0 {
		contextID := ber.NewString(ber.ClassUniversal, ber.TypePrimative,
			ber.TagOctetString, string(c.ContextID), "ContextID")
		vlvSeq.AppendChild(contextID)
	}

	octetString.AppendChild(vlvSeq)
	p.AppendChild(octetString)

	if VlvDebug {
		ber.PrintPacket(p)
	}

	return p, nil

}

func (c *ControlVlvRequest) GetControlType() string {
	return ControlTypeMap[ControlTypeVlvRequest]
}

func (c *ControlVlvRequest) String() string {
	ctext := fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t, BeforeCount: %d, AfterCount: %d"+
			", ByOffset.Offset: %d, ByOffset.ContentCount: %d, GreaterThanOrEqual: %s",
		ControlTypeMap[ControlTypeVlvRequest],
		ControlTypeVlvRequest,
		c.Criticality, c.BeforeCount, c.AfterCount, c.ByOffset.Offset,
		c.ByOffset.ContentCount, c.GreaterThanOrEqual,
	)
	return ctext
}

/***********************************/
/*      RESPONSE CONTROLS          */
/***********************************/

/**************************/
/* ServerSideSortResponse */
/**************************/

type ControlServerSideSortResponse struct {
	AttributeName string // Optional
	Criticality   bool
	Err           error
}

//SortResult ::= SEQUENCE {
//   sortResult  ENUMERATED {
//       success                   (0), -- results are sorted
//       operationsError           (1), -- server internal failure
//       timeLimitExceeded         (3), -- timelimit reached before
//                                      -- sorting was completed
//       strongAuthRequired        (8), -- refused to return sorted
//                                      -- results via insecure
//                                      -- protocol
//       adminLimitExceeded       (11), -- too many matching entries
//                                      -- for the server to sort
//       noSuchAttribute          (16), -- unrecognized attribute
//                                      -- type in sort key
//       inappropriateMatching    (18), -- unrecognized or
//                                      -- inappropriate matching
//                                      -- rule in sort key
//       insufficientAccessRights (50), -- refused to return sorted
//                                      -- results to this client
//       busy                     (51), -- too busy to process
//       unwillingToPerform       (53), -- unable to sort
//       other                    (80)
//       },
//   attributeType [0] AttributeDescription OPTIONAL }
func NewControlServerSideSortResponse(p *ber.Packet) (Control, error) {
	c := new(ControlServerSideSortResponse)
	_, criticality, value := decodeControlTypeAndCrit(p)
	c.Criticality = criticality

	if value.Value != nil {
		sortResult := ber.DecodePacket(value.Data.Bytes())
		value.Data.Truncate(0)
		value.Value = nil
		value.AppendChild(sortResult)
	}

	value = value.Children[0]
	value.Description = "ServerSideSortResponse Control Value"

	value.Children[0].Description = "SortResult"
	errNum := uint8(value.Children[0].Value.(uint64))
	c.Err = NewLDAPError(errNum, "")

	if len(value.Children) == 2 {
		value.Children[1].Description = "Attribute Name"
		c.AttributeName = value.Children[1].ValueString()
		value.Children[1].Value = c.AttributeName
	}
	return c, nil
}

func (c *ControlServerSideSortResponse) Encode() (p *ber.Packet, err error) {
	return nil, NewLDAPError(ErrorEncoding, "Encode of Control unsupported.")
}

func (c *ControlServerSideSortResponse) GetControlType() string {
	return ControlTypeServerSideSortResponse
}

func (c *ControlServerSideSortResponse) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %t, AttributeName: %s, ErrorValue: %d",
		ControlTypeMap[ControlTypeServerSideSortResponse],
		ControlTypeServerSideSortResponse,
		c.Criticality,
		c.AttributeName,
		c.Err.(*LDAPError).ResultCode,
	)
}

/***************/
/* VlvResponse */
/***************/

type ControlVlvResponse struct {
	Criticality    bool
	TargetPosition uint64
	ContentCount   uint64
	Err            error // VirtualListViewResult
	ContextID      string
}

/*
 VirtualListViewResponse ::= SEQUENCE {
       targetPosition    INTEGER (0 .. maxInt),
       contentCount     INTEGER (0 .. maxInt),
       virtualListViewResult ENUMERATED {
            success (0),
            operationsError (1),
            protocolError (3),
            unwillingToPerform (53),
            insufficientAccessRights (50),
            timeLimitExceeded (3),
            adminLimitExceeded (11),
            innapropriateMatching (18),
            sortControlMissing (60),
            offsetRangeError (61),
            other(80),
            ... },
       contextID     OCTET STRING OPTIONAL }
*/
func NewControlVlvResponse(p *ber.Packet) (Control, error) {
	c := new(ControlVlvResponse)
	_, criticality, value := decodeControlTypeAndCrit(p)
	c.Criticality = criticality

	if value.Value != nil {
		vlvResult := ber.DecodePacket(value.Data.Bytes())
		value.Data.Truncate(0)
		value.Value = nil
		value.AppendChild(vlvResult)
	}

	value = value.Children[0]
	value.Description = "VlvResponse Control Value"

	value.Children[0].Description = "TargetPosition"
	value.Children[1].Description = "ContentCount"
	value.Children[2].Description = "VirtualListViewResult/Err"

	c.TargetPosition = value.Children[0].Value.(uint64)
	c.ContentCount = value.Children[1].Value.(uint64)

	errNum := uint8(value.Children[2].Value.(uint64))
	c.Err = NewLDAPError(errNum, "")

	if len(value.Children) == 4 {
		value.Children[3].Description = "ContextID"
		c.ContextID = value.Children[3].ValueString()
	}

	return c, nil
}

func (c *ControlVlvResponse) Encode() (p *ber.Packet, err error) {
	return nil, NewLDAPError(ErrorEncoding, "Encode of Control unsupported.")
}

func (c *ControlVlvResponse) GetControlType() string {
	return ControlTypeVlvResponse
}

func (c *ControlVlvResponse) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %t, TargetPosition: %d, ContentCount: %d, ErrorValue: %d, ContextID: %s",
		ControlTypeMap[ControlTypeVlvResponse],
		ControlTypeVlvResponse,
		c.Criticality,
		c.TargetPosition,
		c.ContentCount,
		c.Err.(*LDAPError).ResultCode,
		c.ContextID,
	)
}
