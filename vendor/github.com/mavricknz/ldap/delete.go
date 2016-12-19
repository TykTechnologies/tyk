// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"github.com/mavricknz/asn1-ber"
)

type DeleteRequest struct {
	DN       string
	Controls []Control
}

func (req *DeleteRequest) RecordType() uint8 {
	return DeleteRecord
}

/*
Simple delete
*/

func (l *LDAPConnection) Delete(delReq *DeleteRequest) (error error) {
	messageID, ok := l.nextMessageID()
	if !ok {
		return NewLDAPError(ErrorClosing, "MessageID channel is closed.")
	}
	encodedDelete := ber.NewString(ber.ClassApplication, ber.TypePrimative, ApplicationDelRequest, delReq.DN, ApplicationMap[ApplicationDelRequest])

	packet, err := requestBuildPacket(messageID, encodedDelete, delReq.Controls)
	if err != nil {
		return err
	}

	return l.sendReqRespPacket(messageID, packet)
}

func NewDeleteRequest(dn string) (delReq *DeleteRequest) {
	delReq = &DeleteRequest{DN: dn, Controls: make([]Control, 0)}
	return
}

// TDDO make generic for mod/del/search via interface.
func (delReq *DeleteRequest) AddControl(control Control) {
	if delReq.Controls == nil {
		delReq.Controls = make([]Control, 0)
	}
	delReq.Controls = append(delReq.Controls, control)
}
