// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains Bind functionality
package ldap

import (
	"github.com/mavricknz/asn1-ber"
)

/*
Simple bind to the server. If using a timeout you should close the connection
on a bind failure.
*/
func (l *LDAPConnection) Bind(username, password string) error {
	messageID, ok := l.nextMessageID()
	if !ok {
		return NewLDAPError(ErrorClosing, "MessageID channel is closed.")
	}

	encodedBind := encodeSimpleBindRequest(username, password)

	packet, err := requestBuildPacket(messageID, encodedBind, nil)
	if err != nil {
		return err
	}

	return l.sendReqRespPacket(messageID, packet)

}

func encodeSimpleBindRequest(username, password string) (bindRequest *ber.Packet) {
	bindRequest = ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, username, "User Name"))
	bindRequest.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, password, "Password"))
	return
}
