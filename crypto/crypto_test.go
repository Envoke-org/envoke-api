package crypto

import (
	"bytes"
	. "github.com/Envoke-org/envoke-api/common"
	cc "github.com/Envoke-org/envoke-api/crypto/conditions"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
	"github.com/Envoke-org/envoke-api/crypto/rsa"
	"sort"
	"testing"
)

func TestCrypto(t *testing.T) {
	// RSA-PEM encoding
	privRSA, pubRSA := rsa.GenerateKeypair()
	privPEM := privRSA.MarshalPEM()
	if err := privRSA.UnmarshalPEM(privPEM); err != nil {
		t.Fatal(err)
	}
	pubPEM := pubRSA.MarshalPEM()
	if err := pubRSA.UnmarshalPEM(pubPEM); err != nil {
		t.Fatal(err)
	}
	// Sha256 Pre-Image
	preimage := []byte("helloworld")
	f1 := cc.NewFulfillmentPreImage(preimage, 1)
	// Validate the fulfillment
	if !f1.Validate(preimage) {
		t.Fatal("Failed to validate pre-image fulfillment")
	}
	// Sha256 Prefix
	prefix := []byte("hello")
	suffix := []byte("world")
	f2 := cc.NewFulfillmentPrefix(prefix, f1, 1)
	// Validate the fulfillment
	if !f2.Validate(suffix) {
		t.Fatal("Failed to validate prefix fulfillment")
	}
	// Ed25519
	msg := []byte("deadbeef")
	privEd25519, _ := ed25519.GenerateKeypairFromPassword("password")
	f3 := cc.FulfillmentFromPrivKey(msg, privEd25519, 2)
	if !f3.Validate(msg) {
		t.Fatal("Failed to validate ed25519 fulfillment")
	}
	// RSA
	anotherMsg := []byte("foobar")
	f4 := cc.FulfillmentFromPrivKey(anotherMsg, privRSA, 1)
	if !f4.Validate(anotherMsg) {
		t.Fatal("Failed to validate pre-image fulfillment")
	}
	// Sha256 Threshold
	subs := cc.Fulfillments{f1, f2, f3, f4}
	sort.Sort(subs)
	threshold := 4
	f5 := cc.NewFulfillmentThreshold(subs, threshold, 1)
	buf := new(bytes.Buffer)
	WriteVarOctet(buf, msg)
	WriteVarOctet(buf, preimage)
	WriteVarOctet(buf, suffix)
	WriteVarOctet(buf, anotherMsg)
	if !f5.Validate(buf.Bytes()) {
		t.Fatal("Failed to validate threshold fulfillment")
	}
	// Get fulfillment uri
	uri := f5.String()
	// Derive new fulfillment from uri, use same weight
	f6, err := cc.UnmarshalURI(uri, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Check whether hashes are the same
	if !bytes.Equal(f5.Hash(), f6.Hash()) {
		t.Fatal("Expected identical fulfillment hashes")
	}
	// Nested Thresholds
	subs = cc.Fulfillments{f1, f2, f3, f4, f5}
	sort.Sort(subs)
	buf2 := new(bytes.Buffer)
	WriteVarOctet(buf2, msg)
	WriteVarOctet(buf2, preimage)
	WriteVarOctet(buf2, suffix)
	WriteVarOctet(buf2, buf.Bytes())
	WriteVarOctet(buf2, anotherMsg)
	threshold = 4
	f7 := cc.NewFulfillmentThreshold(subs, threshold, 1)
	if !f7.Validate(buf2.Bytes()) {
		t.Fatal("Failed to validate nested thresholds")
	}
}
