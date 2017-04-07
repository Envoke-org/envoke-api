package bigchain

import (
	"testing"

	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
)

var (
	Alice = "3k9RQZGU36rwRV7zHJCMVmcdSVLqtgLJNBWV6e3DPKJi"
	Bob   = "AS7E9tT8hmG7kMThCfdzyCy4RTq1AnMNXpJZFhcu3bwi"
)

func TestBigchain(t *testing.T) {
	output := MustOpenWriteFile("output.json")
	// Keys
	privAlice, pubAlice := ed25519.GenerateKeypairFromSeed(BytesFromB58(Alice))
	privBob, pubBob := ed25519.GenerateKeypairFromSeed(BytesFromB58(Bob))
	// Data
	data := Data{"bees": "knees"}
	// Individual create tx
	tx := IndividualCreateTx(100, data, pubAlice, pubAlice)
	FulfillTx(tx, privAlice)
	// Check that it's fulfilled
	if !FulfilledTx(tx) {
		t.Fatal(ErrInvalidFulfillment)
	}
	WriteJSON(output, Data{"createTx": tx})
	createTxId, err := HttpPostTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	// Divisible transfer tx
	tx = DivisibleTransferTx([]int{40, 60}, createTxId, createTxId, 0, []crypto.PublicKey{pubAlice, pubBob}, pubAlice)
	FulfillTx(tx, privAlice)
	if !FulfilledTx(tx) {
		t.Fatal(ErrInvalidFulfillment)
	}
	transferTxId, err := HttpPostTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"transfer1Tx": tx})
	// Transfer Bob's output of divisible transfer to Alice
	tx = IndividualTransferTx(60, createTxId, transferTxId, 1, pubAlice, pubBob)
	FulfillTx(tx, privBob)
	if !FulfilledTx(tx) {
		t.Fatal(ErrInvalidFulfillment)
	}
	if _, err := HttpPostTx(tx); err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"transfer2Tx": tx})
	// Multiple owners create tx
	tx = MultipleOwnersCreateTx([]int{2, 3}, data, []crypto.PublicKey{pubAlice, pubBob}, pubAlice)
	FulfillTx(tx, privAlice)
	if !FulfilledTx(tx) {
		t.Fatal(ErrInvalidFulfillment)
	}
	if _, err := HttpPostTx(tx); err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"multipleOwnersTx": tx})
	// Multiple owners tx with shared output/threshold signature
	tx = MultipleOwnersCreateTx([]int{100}, data, []crypto.PublicKey{pubAlice, pubBob}, pubAlice)
	FulfillTx(tx, privAlice)
	if !FulfilledTx(tx) {
		t.Fatal(ErrInvalidFulfillment)
	}
	if _, err := HttpPostTx(tx); err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"sharedTx": tx})
}
