// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"github.com/mavricknz/asn1-ber"
)

//ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
//entry           LDAPDN,
//newrdn          RelativeLDAPDN,
//deleteoldrdn    BOOLEAN,
//newSuperior     [0] LDAPDN OPTIONAL }
//
//ModifyDNResponse ::= [APPLICATION 13] LDAPResult

type ModDnRequest struct {
	DN            string
	NewRDN        string
	DeleteOldDn   bool
	NewSuperiorDN string
	Controls      []Control
}

//Untested.
func (l *LDAPConnection) ModDn(req *ModDnRequest) error {
	messageID, ok := l.nextMessageID()
	if !ok {
		return NewLDAPError(ErrorClosing, "MessageID channel is closed.")
	}

	encodedModDn := encodeModDnRequest(req)

	packet, err := requestBuildPacket(messageID, encodedModDn, req.Controls)
	if err != nil {
		return err
	}

	return l.sendReqRespPacket(messageID, packet)
}

func encodeModDnRequest(req *ModDnRequest) (p *ber.Packet) {
	p = ber.Encode(ber.ClassApplication, ber.TypeConstructed,
		ApplicationModifyDNRequest, nil, ApplicationMap[ApplicationModifyDNRequest])
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, req.DN, "LDAPDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, req.NewRDN, "NewRDN"))
	p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimative, ber.TagBoolean, req.DeleteOldDn, "deleteoldrdn"))
	if len(req.NewSuperiorDN) > 0 {
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative,
			ber.TagEOC, req.NewSuperiorDN, "NewSuperiorDN"))
	}
	return
}
