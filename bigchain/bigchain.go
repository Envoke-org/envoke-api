package bigchain

import (
	"bytes"

	. "github.com/Envoke-org/envoke-api/common"
	cc "github.com/Envoke-org/envoke-api/crypto/conditions"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
)

// GET requests

func HttpGetTx(id string) (Data, error) {
	url := Getenv("ENDPOINT") + "transactions/" + id
	response, err := HttpGet(url)
	if err != nil {
		return nil, err
	}
	tx := make(Data)
	if err = ReadJSON(response.Body, &tx); err != nil {
		return nil, err
	}
	if !FulfilledTx(tx) {
		return nil, ErrInvalidFulfillment
	}
	return tx, nil
}

func HttpGetTransfers(assetId string) ([]Data, error) {
	url := Getenv("ENDPOINT") + "transactions?operation=TRANSFER&asset_id=" + assetId
	response, err := HttpGet(url)
	if err != nil {
		return nil, err
	}
	var txs []Data
	if err = ReadJSON(response.Body, &txs); err != nil {
		return nil, err
	}
	for _, tx := range txs {
		if !FulfilledTx(tx) {
			return nil, ErrInvalidFulfillment
		}
	}
	return txs, nil
}

func HttpGetOutputs(pub crypto.PublicKey) ([]string, error) {
	url := Getenv("ENDPOINT") + Sprintf("outputs?public_key=%v", pub)
	response, err := HttpGet(url)
	if err != nil {
		return nil, err
	}
	var links []string
	if err = ReadJSON(response.Body, &links); err != nil {
		return nil, err
	}
	return links, nil
}

func HttpGetFilter(fn func(string) (Data, error), pub crypto.PublicKey) ([]Data, error) {
	links, err := HttpGetOutputs(pub)
	if err != nil {
		return nil, err
	}
	var datas []Data
	for _, link := range links {
		txId := SubmatchStr(`transactions/(.*?)/outputs`, link)[1]
		tx, err := fn(txId)
		if err == nil {
			datas = append(datas, GetTxAssetData(tx))
		}
	}
	return datas, nil
}

// POST request

func HttpPostTx(tx Data) (string, error) {
	url := Getenv("ENDPOINT") + "transactions/"
	buf := new(bytes.Buffer)
	buf.Write(MustMarshalJSON(tx))
	response, err := HttpPost(url, "application/json", buf)
	if err != nil {
		return "", err
	}
	if err := ReadJSON(response.Body, &tx); err != nil {
		return "", err
	}
	return GetTxId(tx), nil
}

// BigchainDB transaction type
// docs.bigchaindb.com/projects/py-driver/en/latest/handcraft.html

const (
	CREATE   = "CREATE"
	GENESIS  = "GENSIS"
	TRANSFER = "TRANSFER"
	VERSION  = "0.9"
)

func DefaultIndividualCreateTx(data Data, owner crypto.PublicKey) (Data, error) {
	return IndividualCreateTx(1, data, owner, owner)
}

func IndividualCreateTx(amount int, data Data, ownerAfter, ownerBefore crypto.PublicKey) (Data, error) {
	amounts := []int{amount}
	asset := Data{"data": data}
	fulfills := []Data{nil}
	ownersAfter := [][]crypto.PublicKey{[]crypto.PublicKey{ownerAfter}}
	ownersBefore := [][]crypto.PublicKey{[]crypto.PublicKey{ownerBefore}}
	return CreateTx(amounts, asset, fulfills, ownersAfter, ownersBefore)
}

func DefaultMultipleOwnersCreateTx(data Data, ownersAfter []crypto.PublicKey, ownerBefore crypto.PublicKey) (Data, error) {
	return MultipleOwnersCreateTx([]int{1}, data, ownersAfter, ownerBefore)
}

func MultipleOwnersCreateTx(amounts []int, data Data, ownersAfter []crypto.PublicKey, ownerBefore crypto.PublicKey) (Data, error) {
	asset := Data{"data": data}
	fulfills := []Data{nil}
	ownersBefore := []crypto.PublicKey{ownerBefore}
	n := len(ownersAfter)
	if n == 0 {
		return nil, Error("no ownersAfter")
	}
	owners := make([][]crypto.PublicKey, n)
	if n == 1 {
		owners[0] = ownersAfter
	} else {
		if n != len(amounts) {
			return nil, Error("different number of ownersAfter and amounts")
		}
		for i, owner := range ownersAfter {
			owners[i] = []crypto.PublicKey{owner}
		}
	}
	return CreateTx(amounts, asset, fulfills, owners, [][]crypto.PublicKey{ownersBefore})
}

func DefaultIndividualTransferTx(assetId, consumeId string, idx int, ownerAfter, ownerBefore crypto.PublicKey) (Data, error) {
	return IndividualTransferTx(1, assetId, consumeId, idx, ownerAfter, ownerBefore)
}

func IndividualTransferTx(amount int, assetId, consumeId string, idx int, ownerAfter, ownerBefore crypto.PublicKey) (Data, error) {
	amounts := []int{amount}
	asset := Data{"id": assetId}
	fulfills := []Data{Data{"txid": consumeId, "output": idx}}
	ownersAfter := [][]crypto.PublicKey{[]crypto.PublicKey{ownerAfter}}
	ownersBefore := [][]crypto.PublicKey{[]crypto.PublicKey{ownerBefore}}
	return TransferTx(amounts, asset, fulfills, ownersAfter, ownersBefore)
}

func DivisibleTransferTx(amounts []int, assetId, consumeId string, idx int, ownersAfter []crypto.PublicKey, ownerBefore crypto.PublicKey) (Data, error) {
	n := len(ownersAfter)
	if n <= 1 {
		return nil, Error("must be multiple ownersAfter")
	}
	if n != len(amounts) {
		return nil, Error("different number of ownersAfter and amounts")
	}
	asset := Data{"id": assetId}
	fulfills := []Data{Data{"txid": consumeId, "output": idx}}
	owners := make([][]crypto.PublicKey, len(ownersAfter))
	for i, owner := range ownersAfter {
		owners[i] = []crypto.PublicKey{owner}
	}
	ownersBefore := [][]crypto.PublicKey{[]crypto.PublicKey{ownerBefore}}
	return TransferTx(amounts, asset, fulfills, owners, ownersBefore)
}

func CreateTx(amounts []int, asset Data, fulfills []Data, ownersAfter, ownersBefore [][]crypto.PublicKey) (Data, error) {
	return GenerateTx(amounts, asset, fulfills, nil, CREATE, ownersAfter, ownersBefore)
}

func TransferTx(amounts []int, asset Data, fulfills []Data, ownersAfter, ownersBefore [][]crypto.PublicKey) (Data, error) {
	return GenerateTx(amounts, asset, fulfills, nil, TRANSFER, ownersAfter, ownersBefore)
}

func GenerateTx(amounts []int, asset Data, fulfills []Data, metadata Data, operation string, ownersAfter, ownersBefore [][]crypto.PublicKey) (Data, error) {
	inputs := NewInputs(fulfills, ownersBefore)
	outputs, err := NewOutputs(amounts, ownersAfter)
	if err != nil {
		return nil, err
	}
	return NewTx(asset, inputs, metadata, operation, outputs), nil
}

func NewTx(asset Data, inputs []Data, metadata Data, operation string, outputs []Data) Data {
	tx := Data{
		"asset":     asset,
		"inputs":    inputs,
		"metadata":  metadata,
		"operation": operation,
		"outputs":   outputs,
		"version":   VERSION,
	}
	tx.Set("id", BytesToHex(Checksum256(MustMarshalJSON(tx))))
	return tx
}

func FulfillTx(tx Data, privkey crypto.PrivateKey) {
	for _, input := range GetTxInputs(tx) {
		input.Set("fulfillment", cc.DefaultFulfillmentFromPrivKey(MustMarshalJSON(tx), privkey).String())
	}
}

func UnfulfillTx(tx Data) {
	for _, input := range GetTxInputs(tx) {
		input.Clear("fulfillment")
	}
}

func FulfilledTx(tx Data) bool {
	var err error
	inputs := tx.GetDataSlice("inputs")
	fulfillments := make([]cc.Fulfillment, len(inputs))
	for i, input := range inputs {
		uri := input.GetStr("fulfillment")
		fulfillments[i], err = cc.DefaultUnmarshalURI(uri)
		Check(err)
		input.Clear("fulfillment")
	}
	fulfilled := true
	json := MustMarshalJSON(tx)
	for _, f := range fulfillments {
		if !f.Validate(json) {
			fulfilled = false
			break
		}
	}
	for i, input := range inputs {
		input.Set("fulfillment", fulfillments[i].String())
	}
	return fulfilled
}

func NewInputs(fulfills []Data, ownersBefore [][]crypto.PublicKey) []Data {
	n := len(fulfills)
	if n != len(ownersBefore) {
		panic(ErrorAppend(ErrInvalidSize, "slices are different sizes"))
	}
	inputs := make([]Data, n)
	for i := range inputs {
		inputs[i] = NewInput(fulfills[i], ownersBefore[i])
	}
	return inputs
}

func NewInput(fulfills Data, ownersBefore []crypto.PublicKey) Data {
	return Data{
		"fulfillment":   nil,
		"fulfills":      fulfills,
		"owners_before": ownersBefore,
	}
}

func NewOutputs(amounts []int, ownersAfter [][]crypto.PublicKey) ([]Data, error) {
	n := len(ownersAfter)
	if n != len(amounts) {
		return nil, Error("different number of ownersAfter and amounts")
	}
	outputs := make([]Data, n)
	for i, owner := range ownersAfter {
		outputs[i] = NewOutput(amounts[i], owner)
	}
	return outputs, nil
}

func NewOutput(amount int, ownersAfter []crypto.PublicKey) Data {
	n := len(ownersAfter)
	if n == 0 {
		return nil
	}
	if n == 1 {
		return Data{
			"amount":      amount,
			"condition":   cc.DefaultFulfillmentFromPubKey(ownersAfter[0]).Data(),
			"public_keys": ownersAfter,
		}
	}
	return Data{
		"amount":      amount,
		"condition":   cc.DefaultFulfillmentThresholdFromPubKeys(ownersAfter).Data(),
		"public_keys": ownersAfter,
	}
}

//---------------------------------------------------------------------------------------

// For convenience

func DefaultTxOwnerBefore(tx Data) crypto.PublicKey {
	return DefaultInputOwnerBefore(GetTxInput(tx, 0))
}

func DefaultTxOwnerAfter(tx Data, idx int) crypto.PublicKey {
	return DefaultOutputOwnerAfter(GetTxOutput(tx, idx))
}

func DefaultTxConsume(tx Data) Data {
	return GetInputFulfills(GetTxInput(tx, 0))
}

// Tx

func GetTxAssetData(tx Data) Data {
	return tx.GetData("asset").GetData("data")
}

func GetTxAssetId(tx Data) string {
	return tx.GetData("asset").GetStr("id")
}

func GetTxId(tx Data) string {
	return tx.GetStr("id")
}

func GetTxInput(tx Data, idx int) Data {
	return GetTxInputs(tx)[idx]
}

func GetTxInputs(tx Data) []Data {
	return tx.GetDataSlice("inputs")
}

func GetTxOperation(tx Data) string {
	return tx.GetStr("operation")
}

func GetTxOutput(tx Data, idx int) Data {
	return GetTxOutputs(tx)[idx]
}

func GetTxOutputs(tx Data) []Data {
	return tx.GetDataSlice("outputs")
}

// Inputs

func GetInputFulfills(input Data) Data {
	return input.GetData("fulfills")
}

func DefaultInputOwnerBefore(input Data) crypto.PublicKey {
	return GetInputOwnerBefore(input, 0)
}

func GetInputOwnerBefore(input Data, idx int) crypto.PublicKey {
	return GetInputOwnersBefore(input)[idx]
}

func GetInputOwnersBefore(input Data) []crypto.PublicKey {
	if pubkeys, ok := input.Get("owners_before").([]crypto.PublicKey); ok {
		return pubkeys
	}
	ownersBefore := input.GetStrSlice("owners_before")
	pubkeys := make([]crypto.PublicKey, len(ownersBefore))
	for i, owner := range ownersBefore {
		pubkeys[i] = new(ed25519.PublicKey)
		pubkeys[i].FromString(owner)
	}
	return pubkeys
}

// Outputs

func GetOutputAmount(output Data) int {
	return output.GetInt("amount")
}

func GetOutputCondition(output Data) Data {
	return output.GetData("condition")
}

func DefaultOutputOwnerAfter(output Data) crypto.PublicKey {
	return GetOutputOwnerAfter(output, 0)
}

func GetOutputOwnerAfter(output Data, idx int) crypto.PublicKey {
	return GetOutputOwnersAfter(output)[idx]
}

func GetOutputOwnersAfter(output Data) []crypto.PublicKey {
	if pubkeys, ok := output.Get("public_keys").([]crypto.PublicKey); ok {
		return pubkeys
	}
	ownersAfter := output.GetStrSlice("public_keys")
	pubkeys := make([]crypto.PublicKey, len(ownersAfter))
	for i, owner := range ownersAfter {
		pubkeys[i] = new(ed25519.PublicKey)
		pubkeys[i].FromString(owner)
	}
	return pubkeys
}
