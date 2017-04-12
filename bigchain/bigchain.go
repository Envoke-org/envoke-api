package bigchain

import (
	"bytes"

	. "github.com/Envoke-org/envoke-api/common"
	cc "github.com/Envoke-org/envoke-api/crypto/conditions"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
)

// GET requests

func HttpGetTx(txId string) (Data, error) {
	url := Getenv("ENDPOINT") + "transactions/" + txId
	response, err := HttpGet(url)
	if err != nil {
		return nil, err
	}
	tx := make(Data)
	if err = ReadJSON(response.Body, &tx); err != nil {
		return nil, err
	}
	fulfilled, err := FulfilledTx(tx)
	if err != nil {
		return nil, err
	}
	if !fulfilled {
		return nil, Error("unfulfilled")
	}
	return tx, nil
}

func HttpGetStatus(txId string) (string, error) {
	url := Getenv("ENDPOINT") + "statuses?tx_id=" + txId
	response, err := HttpGet(url)
	if err != nil {
		return "", err
	}
	var message Data
	if err = ReadJSON(response.Body, &message); err != nil {
		return "", err
	}
	return message.GetStr("status"), nil
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
		fulfilled, err := FulfilledTx(tx)
		if err != nil {
			return nil, err
		}
		if !fulfilled {
			return nil, Error("unfulfilled")
		}
	}
	return txs, nil
}

func HttpGetOutputs(pubkey crypto.PublicKey, unspent bool) ([]string, []int, error) {
	url := Getenv("ENDPOINT") + Sprintf("outputs?public_key=%v&unspent=%v", pubkey, unspent)
	response, err := HttpGet(url)
	if err != nil {
		return nil, nil, err
	}
	var links []string
	if err = ReadJSON(response.Body, &links); err != nil {
		return nil, nil, err
	}
	txIds := make([]string, len(links))
	outputs := make([]int, len(links))
	for i, link := range links {
		submatch := SubmatchStr(`transactions/(.*?)/outputs/([0-9]{1,2})`, link)
		txIds[i], outputs[i] = submatch[1], MustAtoi(submatch[2])
	}
	return txIds, outputs, nil
}

func HttpGetFilter(fn func(string) (Data, error), pubkey crypto.PublicKey, unspent bool) ([]Data, error) {
	txIds, _, err := HttpGetOutputs(pubkey, unspent)
	if err != nil {
		return nil, err
	}
	var datas []Data
	for _, txId := range txIds {
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

func CreateTx(amounts []int, data Data, ownersAfter []crypto.PublicKey, ownersBefore []crypto.PublicKey) (Data, error) {
	asset := Data{"data": data}
	fulfills := []Data{nil}
	if len(amounts) == 0 {
		return nil, Error("no amounts")
	}
	_ownersAfter := make([][]crypto.PublicKey, len(amounts))
	if len(amounts) == 1 {
		_ownersAfter[0] = ownersAfter
	} else {
		if len(amounts) != len(ownersAfter) {
			return nil, Error("different number of amounts and ownersAfter")
		}
		for i, ownerAfter := range ownersAfter {
			_ownersAfter[i] = []crypto.PublicKey{ownerAfter}
		}
	}
	return GenerateTx(amounts, asset, fulfills, nil, CREATE, _ownersAfter, [][]crypto.PublicKey{ownersBefore})
}
func TransferTx(amounts []int, assetId, consumeId string, idx int, ownersAfter []crypto.PublicKey, ownersBefore []crypto.PublicKey) (Data, error) {
	if len(amounts) == 0 {
		return nil, Error("no amounts")
	}
	if len(amounts) != len(ownersAfter) {
		return nil, Error("different number of amounts and ownersAfter")
	}
	asset := Data{"id": assetId}
	fulfills := []Data{Data{"txid": consumeId, "output": idx}}
	_ownersAfter := make([][]crypto.PublicKey, len(ownersAfter))
	for i, ownerAfter := range ownersAfter {
		_ownersAfter[i] = []crypto.PublicKey{ownerAfter}
	}
	return GenerateTx(amounts, asset, fulfills, nil, TRANSFER, _ownersAfter, [][]crypto.PublicKey{ownersBefore})
}

func GenerateTx(amounts []int, asset Data, fulfills []Data, metadata Data, operation string, ownersAfter, ownersBefore [][]crypto.PublicKey) (Data, error) {
	inputs, err := NewInputs(fulfills, ownersBefore)
	if err != nil {
		return nil, err
	}
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

func IndividualFulfillTx(tx Data, privkey crypto.PrivateKey) error {
	fulfillment, err := cc.DefaultFulfillmentFromPrivkey(MustMarshalJSON(tx), privkey)
	if err != nil {
		return err
	}
	return FulfillTx(tx, cc.Fulfillments{fulfillment})
}

func MultipleFulfillTx(tx Data, pubkeys []crypto.PublicKey, signatures []string) error {
	if len(pubkeys) == 0 {
		return Error("no pubkeys")
	}
	if len(pubkeys) != len(signatures) {
		return Error("different number of pubkeys and signatures")
	}
	sig := new(ed25519.Signature)
	subs := make(cc.Fulfillments, len(pubkeys))
	for i, pubkey := range pubkeys {
		if err := sig.FromString(signatures[i]); err != nil {
			return err
		}
		subs[i] = cc.DefaultFulfillmentEd25519(pubkey.(*ed25519.PublicKey), sig)
	}
	return FulfillTx(tx, cc.Fulfillments{cc.DefaultFulfillmentThreshold(subs)})
}

func FulfillTx(tx Data, fulfillments cc.Fulfillments) error {
	if len(fulfillments) == 0 {
		return Error("no fulfillments")
	}
	inputs := GetTxInputs(tx)
	if len(fulfillments) != len(inputs) {
		return Error("different number of fulfillments and inputs")
	}
	for i, fulfillment := range fulfillments {
		inputs[i].Set("fulfillment", fulfillment.String())
	}
	return nil
}

func UnfulfillTx(tx Data) (_ cc.Fulfillments, err error) {
	inputs := GetTxInputs(tx)
	if len(inputs) == 0 {
		return nil, Error("no inputs")
	}
	fulfillments := make(cc.Fulfillments, len(inputs))
	for i, input := range inputs {
		uri := input.GetStr("fulfillment")
		fulfillments[i], err = cc.DefaultUnmarshalURI(uri)
		if err != nil {
			// PrintJSON(inputs)
			return nil, err
		}
		input.Clear("fulfillment")
	}
	return fulfillments, nil
}

func FulfilledTx(tx Data) (bool, error) {
	fulfillments, err := UnfulfillTx(tx)
	if err != nil {
		return false, err
	}
	fulfilled := true
	p := MustMarshalJSON(tx)
	for _, fulfillment := range fulfillments {
		if subs := fulfillment.Subfulfillments(); subs != nil {
			for _, sub := range subs {
				if !sub.Validate(p) {
					fulfilled = false
					break
				}
			}
		} else if !fulfillment.Validate(p) {
			fulfilled = false
			break
		}
	}
	if err = FulfillTx(tx, fulfillments); err != nil {
		return false, err
	}
	return fulfilled, nil
}

func NewInputs(fulfills []Data, ownersBefore [][]crypto.PublicKey) ([]Data, error) {
	if len(fulfills) == 0 {
		return nil, Error("no fulfills")
	}
	if len(fulfills) != len(ownersBefore) {
		return nil, Error("different number of fulfills and ownersBefore")
	}
	inputs := make([]Data, len(fulfills))
	for i := range inputs {
		inputs[i] = NewInput(fulfills[i], ownersBefore[i])
	}
	return inputs, nil
}

func NewInput(fulfills Data, ownersBefore []crypto.PublicKey) Data {
	return Data{
		"fulfillment":   nil,
		"fulfills":      fulfills,
		"owners_before": ownersBefore,
	}
}

func NewOutputs(amounts []int, ownersAfter [][]crypto.PublicKey) (_ []Data, err error) {
	if len(amounts) == 0 {
		return nil, Error("no amounts")
	}
	if len(amounts) != len(ownersAfter) {
		return nil, Error("different number of amounts and ownersAfter")
	}
	outputs := make([]Data, len(amounts))
	for i, owner := range ownersAfter {
		outputs[i], err = NewOutput(amounts[i], owner)
		if err != nil {
			return nil, err
		}
	}
	return outputs, nil
}

func NewOutput(amount int, ownersAfter []crypto.PublicKey) (_ Data, err error) {
	if len(ownersAfter) == 0 {
		return nil, Error("no ownersAfter")
	}
	var fulfillment cc.Fulfillment
	if len(ownersAfter) == 1 {
		fulfillment, err = cc.DefaultFulfillmentFromPubkey(ownersAfter[0])
		if err != nil {
			return nil, err
		}
	} else {
		fulfillments := make(cc.Fulfillments, len(ownersAfter))
		for i, ownerAfter := range ownersAfter {
			fulfillments[i], err = cc.DefaultFulfillmentFromPubkey(ownerAfter)
			if err != nil {
				return nil, err
			}
		}
		fulfillment = cc.DefaultFulfillmentThreshold(fulfillments)
	}
	return Data{
		"amount":      amount,
		"condition":   fulfillment.Data(),
		"public_keys": ownersAfter,
	}, nil
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
