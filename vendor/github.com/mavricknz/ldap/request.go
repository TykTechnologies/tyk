// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"fmt"
	"github.com/mavricknz/asn1-ber"
	"time"
)

// messageID - messageID obtained from Conn.nextMessageID()
// opPacket - the operation BER encoded Packet e.g. Search/Modify/Delete/Compare
// controls - the controls to add to the Request
// returns the BER encoded LDAP request or an Error
func requestBuildPacket(messageID uint64, opPacket *ber.Packet, controls []Control) (p *ber.Packet, err error) {

	p = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID"))
	p.AppendChild(opPacket)

	if controls != nil && len(controls) > 0 {
		cPacket, err := encodeControls(controls)
		if err != nil {
			return nil, err
		}
		p.AppendChild(cPacket)
	}
	return
}

func (l *LDAPConnection) sendReqRespPacket(messageID uint64, packet *ber.Packet) error {

	if l.Debug {
		ber.PrintPacket(packet)
	}

	channel, err := l.sendMessage(packet)

	if err != nil {
		return err
	}

	if channel == nil {
		return NewLDAPError(ErrorNetwork, "Could not send message")
	}

	defer l.finishMessage(messageID)
	if l.Debug {
		fmt.Printf("%d: waiting for response\n", messageID)
	}

	var responsePacket *ber.Packet = nil
	var ok bool

	// If a timeout is set then use it, else use default.
	timeout := l.ReadTimeout
	if uint64(timeout) == 0 {
		timeout = DefaultTimeout
	}
	select {
	case responsePacket, ok = <-channel:
		if !ok {
			return NewLDAPError(ErrorClosing, "Response Channel Closed")
		}
	case <-time.After(timeout):
		if l.AbandonMessageOnReadTimeout {
			err = l.Abandon(messageID)
			if err != nil {
				return NewLDAPError(ErrorNetwork,
					"Timeout waiting for Message and error on Abandon")
			}
		}
		return NewLDAPError(ErrorNetwork, "Timeout waiting for Message")
	}

	if l.Debug {
		fmt.Printf("%d: got response %p\n", messageID, responsePacket)
	}

	if responsePacket == nil {
		return NewLDAPError(ErrorNetwork, "Could not retrieve message")
	}

	if l.Debug {
		if err := addLDAPDescriptions(responsePacket); err != nil {
			return err
		}
		ber.PrintPacket(responsePacket)
	}

	result_code, result_description := getLDAPResultCode(responsePacket)

	if result_code != 0 {
		return NewLDAPError(result_code, result_description)
	}

	if l.Debug {
		fmt.Printf("%d: returning\n", messageID)
	}
	return nil
}
