package kafka

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/xdg-go/scram"
)

// SHA256 generates the SHA256 hash.
var SHA256 scram.HashGeneratorFcn = sha256.New

// SHA512 generates the SHA512 hash.
var SHA512 scram.HashGeneratorFcn = sha512.New

// XDGSCRAMClient represents struct to XDG Scram client to initialize conversation.
type XDGSCRAMClient struct {
	*scram.Client
	*scram.ClientConversation
	scram.HashGeneratorFcn
}

// Begin initializes new client and conversation to securely transmit the provided credentials to Kafka.
func (x *XDGSCRAMClient) Begin(userName, password, authzID string) (err error) {
	x.Client, err = x.NewClient(userName, password, authzID)
	if err != nil {
		return err
	}
	x.ClientConversation = x.NewConversation()
	return nil
}

// Step takes a string provided from a server (or just an empty string for the very first conversation step)
// and attempts to move the authentication conversation forward.
func (x *XDGSCRAMClient) Step(challenge string) (response string, err error) {
	response, err = x.ClientConversation.Step(challenge)
	return
}

// Done returns true if the conversation is completed or has errored.
func (x *XDGSCRAMClient) Done() bool {
	return x.ClientConversation.Done()
}
