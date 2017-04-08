package bigchain

import (
	"testing"

	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
)

var (
	Alice = "3th33iKfYoPXQ6YL8mXcD3gzgMppEEHFBPFqch4Cn5d3"
	Bob   = "4ScATKswfFYUw3FDoxDoUWsRzBh3BUqTmizmCBNRoPiz"
)

func TestBigchain(t *testing.T) {
	output := MustOpenWriteFile("output.json")
	// Keys
	privAlice, pubAlice := ed25519.GenerateKeypairFromSeed(BytesFromB58(Alice))
	privBob, pubBob := ed25519.GenerateKeypairFromSeed(BytesFromB58(Bob))
	// Data
	data := Data{"bees": "knees"}
	// Individual create tx
	tx, err := IndividualCreateTx(100, data, pubAlice, pubAlice)
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privAlice); err != nil {
		t.Fatal(err)
	}
	// Check that it's fulfilled
	fulfilled, err := FulfilledTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	if !fulfilled {
		t.Fatal("unfulfilled")
	}
	WriteJSON(output, Data{"createTx": tx})
	SleepSeconds(1)
	createTxId, err := HttpPostTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	// Divisible transfer tx
	tx, err = DivisibleTransferTx([]int{40, 60}, createTxId, createTxId, 0, []crypto.PublicKey{pubAlice, pubBob}, pubAlice)
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privAlice); err != nil {
		t.Fatal(err)
	}
	fulfilled, err = FulfilledTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	if !fulfilled {
		t.Fatal("unfulfilled")
	}
	transferTxId, err := HttpPostTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"transfer1Tx": tx})
	SleepSeconds(1)
	// Transfer Bob's output of divisible transfer to Alice
	tx, err = IndividualTransferTx(60, createTxId, transferTxId, 1, pubAlice, pubBob)
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privBob); err != nil {
		t.Fatal(err)
	}
	fulfilled, err = FulfilledTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	if !fulfilled {
		t.Fatal("unfulfilled")
	}
	if _, err := HttpPostTx(tx); err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"transfer2Tx": tx})
	SleepSeconds(1)
	// Multiple outputs tx
	tx, err = MultipleOwnersCreateTx([]int{2, 3}, data, []crypto.PublicKey{pubAlice, pubBob}, []crypto.PublicKey{pubAlice})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privAlice); err != nil {
		t.Fatal(err)
	}
	fulfilled, err = FulfilledTx(tx)
	if err != nil {
		t.Fatal(ErrInvalidFulfillment)
	}
	if !fulfilled {
		t.Fatal("unfulfilled")
	}
	if _, err := HttpPostTx(tx); err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"multipleOutputTx": tx})
	SleepSeconds(1)
	// Shared input tx
	tx, err = MultipleOwnersCreateTx([]int{1}, data, []crypto.PublicKey{pubAlice}, []crypto.PublicKey{pubAlice, pubBob})
	if err != nil {
		t.Fatal(err)
	}
	p := MustMarshalJSON(tx)
	if err = MultipleFulfillTx(tx, []crypto.PublicKey{pubAlice, pubBob}, []crypto.Signature{privAlice.Sign(p), privBob.Sign(p)}); err != nil {
		t.Fatal(err)
	}
	fulfilled, err = FulfilledTx(tx)
	if err != nil {
		t.Fatal(ErrInvalidFulfillment)
	}
	if !fulfilled {
		t.Fatal("unfulfilled")
	}
	if _, err := HttpPostTx(tx); err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"sharedInputTx": tx})
	SleepSeconds(1)
	// Shared output tx
	tx, err = MultipleOwnersCreateTx([]int{100}, data, []crypto.PublicKey{pubAlice, pubBob}, []crypto.PublicKey{pubAlice})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privAlice); err != nil {
		t.Fatal(err)
	}
	fulfilled, err = FulfilledTx(tx)
	if err != nil {
		t.Fatal(ErrInvalidFulfillment)
	}
	if !fulfilled {
		t.Fatal("unfulfilled")
	}
	if _, err := HttpPostTx(tx); err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"sharedOutputTx": tx})
}
