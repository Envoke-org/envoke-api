package bigchain

import (
	"testing"
	"time"

	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
)

var (
	Alice = "9qLvREC54mhKYivr88VpckyVWdAFmifJpGjbvV5AiTRs"
	Bob   = "4ScA2KswfFYUw3fDoxDodWsRzBh3BUqTmizmCBNRoPi2"
)

func TestBigchain(t *testing.T) {
	output := MustOpenWriteFile("output.json")
	// Keys
	privkeyAlice, pubkeyAlice := ed25519.GenerateKeypairFromSeed(BytesFromB58(Alice))
	privkeyBob, pubkeyBob := ed25519.GenerateKeypairFromSeed(BytesFromB58(Bob))
	// Data
	data := Data{"bees": "knees"}
	// Individual create tx
	tx, err := CreateTx([]int{100}, data, nil, []crypto.PublicKey{pubkeyAlice}, []crypto.PublicKey{pubkeyAlice})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privkeyAlice, NilTime); err != nil {
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
	SleepSeconds(4)
	createTxId, err := HttpPostTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	// Individual create tx with timeout
	tx, err = CreateTx([]int{78}, data, []time.Time{Date(1, 1, 2018, nil)}, []crypto.PublicKey{pubkeyAlice}, []crypto.PublicKey{pubkeyAlice})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privkeyAlice, NilTime); err != nil {
		t.Fatal(err)
	}
	// Check that it's fulfilled
	fulfilled, err = FulfilledTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	if !fulfilled {
		t.Fatal("unfulfilled")
	}
	WriteJSON(output, Data{"timeoutTx": tx})
	SleepSeconds(6)
	if _, err := HttpPostTx(tx); err != nil {
		t.Fatal(err)
	}
	/*
		// Transfer tx with timeout
		tx, err = TransferTx([]int{78}, createTxId, createTxId, nil, 0, []crypto.PublicKey{pubkeyAlice}, []crypto.PublicKey{pubkeyAlice})
		if err != nil {
			t.Fatal(err)
		}
		if err = IndividualFulfillTx(tx, privkeyAlice, Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := HttpPostTx(tx); err != nil {
			t.Fatal(err)
		}
		WriteJSON(output, Data{"transferTimeoutTx": tx})
	*/
	// Divisible transfer tx
	tx, err = TransferTx([]int{40, 60}, createTxId, createTxId, nil, 0, []crypto.PublicKey{pubkeyAlice, pubkeyBob}, []crypto.PublicKey{pubkeyAlice})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privkeyAlice, NilTime); err != nil {
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
	SleepSeconds(4)
	// Transfer Bob's output of divisible transfer to Alice
	tx, err = TransferTx([]int{60}, createTxId, transferTxId, nil, 1, []crypto.PublicKey{pubkeyAlice}, []crypto.PublicKey{pubkeyBob})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privkeyBob, NilTime); err != nil {
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
	SleepSeconds(4)
	// Multiple outputs tx
	tx, err = CreateTx([]int{2, 1}, data, nil, []crypto.PublicKey{pubkeyAlice, pubkeyBob}, []crypto.PublicKey{pubkeyAlice})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privkeyAlice, NilTime); err != nil {
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
	SleepSeconds(4)
	// Shared input tx
	tx, err = CreateTx([]int{1}, data, nil, []crypto.PublicKey{pubkeyAlice}, []crypto.PublicKey{pubkeyAlice, pubkeyBob})
	if err != nil {
		t.Fatal(err)
	}
	p := MustMarshalJSON(tx)
	signatureAlice := privkeyAlice.Sign(p).String()
	signatureBob := privkeyBob.Sign(p).String()
	if err = MultipleFulfillTx(tx, []crypto.PublicKey{pubkeyAlice, pubkeyBob}, []string{signatureAlice, signatureBob}); err != nil {
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
	SleepSeconds(4)
	// Shared output tx
	tx, err = CreateTx([]int{100}, data, nil, []crypto.PublicKey{pubkeyAlice, pubkeyBob}, []crypto.PublicKey{pubkeyAlice})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privkeyAlice, NilTime); err != nil {
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
	SleepSeconds(4)
	// Individual create tx
	tx, err = CreateTx([]int{10}, data, nil, []crypto.PublicKey{pubkeyAlice}, []crypto.PublicKey{pubkeyAlice})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privkeyAlice, NilTime); err != nil {
		t.Fatal(err)
	}
	// Check that it's fulfilled
	fulfilled, err = FulfilledTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	if !fulfilled {
		t.Fatal("unfulfilled")
	}
	createTxId, err = HttpPostTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"anotherCreateTx": tx})
	SleepSeconds(4)
	// Transfer to self
	tx, err = TransferTx([]int{10}, createTxId, createTxId, nil, 0, []crypto.PublicKey{pubkeyAlice}, []crypto.PublicKey{pubkeyAlice})
	if err != nil {
		t.Fatal(err)
	}
	if err = IndividualFulfillTx(tx, privkeyAlice, NilTime); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !fulfilled {
		t.Fatal("unfulfilled")
	}
	if _, err := HttpPostTx(tx); err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"transferSelfTx": tx})
}
