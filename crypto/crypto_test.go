package crypto

import (
	"bytes"
	"sort"
	"testing"
	"time"

	. "github.com/Envoke-org/envoke-api/common"
	cc "github.com/Envoke-org/envoke-api/crypto/conditions"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
	"github.com/Envoke-org/envoke-api/crypto/rsa"
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
	fulfillmentPreimage, err := cc.NewFulfillmentPreImage(preimage, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Validate the fulfillment
	if !fulfillmentPreimage.Validate(preimage) {
		t.Fatal("Failed to validate pre-image fulfillment")
	}
	// Sha256 Prefix
	prefix := []byte("hello")
	suffix := []byte("world")
	fulfillmentPrefix, err := cc.NewFulfillmentPrefix(prefix, fulfillmentPreimage, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Validate the fulfillment
	if !fulfillmentPrefix.Validate(suffix) {
		t.Fatal("Failed to validate prefix fulfillment")
	}
	// Ed25519
	msg := []byte("deadbeef")
	privEd25519, _ := ed25519.GenerateKeypairFromPassword("password")
	fulfillmentEd25519, err := cc.FulfillmentFromPrivkey(msg, privEd25519, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !fulfillmentEd25519.Validate(msg) {
		t.Fatal("Failed to validate ed25519 fulfillment")
	}
	// RSA
	anotherMsg := []byte("foobar")
	fulfillmentRSA, err := cc.FulfillmentFromPrivkey(anotherMsg, privRSA, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !fulfillmentRSA.Validate(anotherMsg) {
		t.Fatal("Failed to validate pre-image fulfillment")
	}
	// Sha256 Threshold
	subs := cc.Fulfillments{fulfillmentPreimage, fulfillmentPrefix, fulfillmentEd25519, fulfillmentRSA}
	sort.Sort(subs)
	threshold := 4
	fulfillmentThreshold, err := cc.NewFulfillmentThreshold(subs, threshold, 1)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	WriteVarOctet(buf, msg)
	WriteVarOctet(buf, preimage)
	WriteVarOctet(buf, suffix)
	WriteVarOctet(buf, anotherMsg)
	if !fulfillmentThreshold.Validate(buf.Bytes()) {
		t.Fatal("Failed to validate threshold fulfillment")
	}
	// Get fulfillment uri
	uri := fulfillmentThreshold.String()
	// Derive new fulfillment from uri, use same weight
	anotherFulfillmentThreshold, err := cc.UnmarshalURI(uri, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Check whether hashes are the same
	if !bytes.Equal(fulfillmentThreshold.Hash(), anotherFulfillmentThreshold.Hash()) {
		t.Fatal("Expected identical fulfillment hashes")
	}
	// Nested Thresholds
	subs = cc.Fulfillments{fulfillmentPreimage, fulfillmentPrefix, fulfillmentEd25519, fulfillmentRSA, fulfillmentThreshold}
	sort.Sort(subs)
	buf2 := new(bytes.Buffer)
	WriteVarOctet(buf2, msg)
	WriteVarOctet(buf2, preimage)
	WriteVarOctet(buf2, suffix)
	WriteVarOctet(buf2, buf.Bytes())
	WriteVarOctet(buf2, anotherMsg)
	threshold = 4
	fulfillmentNestedThresholds, err := cc.NewFulfillmentThreshold(subs, threshold, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !fulfillmentNestedThresholds.Validate(buf2.Bytes()) {
		t.Fatal("Failed to validate nested thresholds")
	}
	// Timeout
	fulfillmentTimeout, err := cc.DefaultFulfillmentTimeout(Date(1, 1, 2018, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !fulfillmentTimeout.Validate([]byte(Timestamp(Date(31, 12, 2017, nil)))) {
		t.Fatal("Failed to validate timeout")
	}
	Println(fulfillmentTimeout, cc.GetCondition(fulfillmentTimeout))
}
