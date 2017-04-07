package linked_data

import (
	"bytes"

	"github.com/Envoke-org/envoke-api/bigchain"
	. "github.com/Envoke-org/envoke-api/common"
	cc "github.com/Envoke-org/envoke-api/crypto/conditions"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
	"github.com/Envoke-org/envoke-api/schema"
	"github.com/Envoke-org/envoke-api/spec"
)

func SetThreshold(data Data, pubkeys []crypto.PublicKey, signatures []string, tx Data) error {
	n := len(pubkeys)
	if n != len(signatures) {
		return Error("different number of pubkeys and signatures")
	}
	digest := Checksum256(MustMarshalJSON(tx))
	sig := new(ed25519.Signature)
	subs := make(cc.Fulfillments, n)
	for i, pubkey := range pubkeys {
		if err := sig.FromString(signatures[i]); err != nil {
			return err
		}
		if !pubkey.Verify(digest, sig) {
			return ErrInvalidSignature
		}
		subs[i] = cc.DefaultFulfillmentEd25519(pubkey.(*ed25519.PublicKey), sig)
	}
	data.Set("thresholdSignature", cc.DefaultFulfillmentThreshold(subs).String())
	return nil
}

func ValidateThreshold(data Data, pubkeys []crypto.PublicKey, tx Data) error {
	thresholdSignature := spec.GetThresholdSignature(data)
	ful, err := cc.DefaultUnmarshalURI(thresholdSignature)
	if err != nil {
		return err
	}
	thresholdFulfillment := cc.DefaultFulfillmentThresholdFromPubKeys(pubkeys)
	if cc.GetCondition(ful).String() != cc.GetCondition(thresholdFulfillment).String() {
		return ErrInvalidCondition
	}
	data.Delete("thresholdSignature")
	txCopy := make(Data)
	for k, v := range tx {
		txCopy[k] = v
	}
	bigchain.UnfulfillTx(txCopy)
	txCopy.Delete("id")
	txCopy.Set("id", BytesToHex(Checksum256(MustMarshalJSON(txCopy))))
	buf := new(bytes.Buffer)
	digest := Checksum256(MustMarshalJSON(txCopy))
	for i := 0; i < len(pubkeys); i++ {
		WriteVarOctet(buf, digest)
	}
	if !ful.Validate(buf.Bytes()) {
		return ErrInvalidFulfillment
	}
	data.Set("thresholdSignature", thresholdSignature)
	return nil
}

func CheckTxOwnerBefore(tx Data) (crypto.PublicKey, error) {
	inputs := bigchain.GetTxInputs(tx)
	if len(inputs) != 1 {
		return nil, Error("should be 1 input")
	}
	ownersBefore := bigchain.GetInputOwnersBefore(inputs[0])
	if len(ownersBefore) != 1 {
		return nil, Error("should be 1 ownerBefore")
	}
	return ownersBefore[0], nil
}

func CheckOutputOwnerAfter(output Data) (crypto.PublicKey, error) {
	ownersAfter := bigchain.GetOutputOwnersAfter(output)
	if len(ownersAfter) != 1 {
		return nil, Error("should be 1 ownerAfter")
	}
	return ownersAfter[0], nil
}

func ValidateUserId(id string) (Data, error) {
	tx, err := bigchain.HttpGetTx(id)
	if err != nil {
		return nil, err
	}
	if err = ValidateUserTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateUserTx(tx Data) (err error) {
	if err := schema.ValidateSchema(bigchain.GetTxAssetData(tx), "user"); err != nil {
		return err
	}
	inputs := bigchain.GetTxInputs(tx)
	if len(inputs) != 1 {
		return Error("should be 1 input")
	}
	ownersBefore := bigchain.GetInputOwnersBefore(inputs[0])
	if len(ownersBefore) != 1 {
		return Error("should be 1 ownerBefore")
	}
	outputs := bigchain.GetTxOutputs(tx)
	if len(outputs) != 1 {
		return Error("should be 1 output")
	}
	ownersAfter := bigchain.GetOutputOwnersAfter(outputs[0])
	if len(ownersAfter) != 1 {
		return Error("should be 1 ownerAfter")
	}
	if !ownersBefore[0].Equals(ownersAfter[0]) {
		return Error("user has different ownerBefore and ownerAfter")
	}
	return nil
}

func BuildCompositionTx(composition Data, signatures []string, splits []int) (Data, error) {
	composers := spec.GetComposers(composition)
	n := len(composers)
	if n == 0 {
		return nil, Error("no composers")
	}
	if n > 1 {
		if signatures != nil {
			if n != len(signatures) {
				return nil, Error("different number of composers and signatures")
			}
		}
		if n != len(splits) {
			return nil, Error("different number of composers and splits")
		}
	}
	composerKeys := make([]crypto.PublicKey, n)
	totalShares := 0
	for i, composer := range composers {
		composerId := spec.GetId(composer)
		tx, err := ValidateUserId(composerId)
		if err != nil {
			return nil, err
		}
		composerKeys[i] = bigchain.DefaultTxOwnerBefore(tx)
		if n > 1 {
			if totalShares += splits[i]; totalShares > 100 {
				return nil, Error("total shares exceed 100")
			}
		}
	}
	if n > 1 {
		if totalShares != 100 {
			return nil, Error("total shares do not equal 100")
		}
	}
	publisherId := spec.GetPublisherId(composition)
	senderKey := composerKeys[0]
	if !EmptyStr(publisherId) {
		tx, err := ValidateUserId(publisherId)
		if err != nil {
			return nil, err
		}
		senderKey = bigchain.DefaultTxOwnerBefore(tx)
	}
	if n == 1 {
		return bigchain.IndividualCreateTx(100, composition, composerKeys[0], senderKey)
	}
	tx, err := bigchain.MultipleOwnersCreateTx(splits, composition, composerKeys, senderKey)
	if err != nil {
		return nil, err
	}
	if signatures != nil {
		if err := SetThreshold(composition, composerKeys, signatures, tx); err != nil {
			return nil, err
		}
		tx, err = bigchain.MultipleOwnersCreateTx(splits, composition, composerKeys, senderKey)
		if err != nil {
			return nil, err
		}
	}
	return tx, nil
}

func ValidateCompositionId(id string) (Data, error) {
	tx, err := bigchain.HttpGetTx(id)
	if err != nil {
		return nil, err
	}
	if err = ValidateCompositionTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateCompositionTx(compositionTx Data) (err error) {
	composition := bigchain.GetTxAssetData(compositionTx)
	if err := schema.ValidateSchema(composition, "composition"); err != nil {
		return err
	}
	composers := spec.GetComposers(composition)
	n := len(composers)
	inputs := bigchain.GetTxInputs(compositionTx)
	if len(inputs) != 1 {
		return Error("should be 1 input")
	}
	ownersBefore := bigchain.GetInputOwnersBefore(inputs[0])
	if len(ownersBefore) != 1 {
		return Error("should be 1 ownerBefore")
	}
	outputs := bigchain.GetTxOutputs(compositionTx)
	if n != len(outputs) {
		return Error("different number of outputs and composers")
	}
	composerKeys := make([]crypto.PublicKey, n)
	totalShares := 0
	for i, composer := range composers {
		tx, err := ValidateUserId(spec.GetId(composer))
		if err != nil {
			return err
		}
		ownersAfter := bigchain.GetOutputOwnersAfter(outputs[i])
		if len(ownersAfter) != 1 {
			return Error("should be 1 ownerAfter")
		}
		if !ownersAfter[0].Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("composer isn't ownerAfter")
		}
		if totalShares += bigchain.GetOutputAmount(outputs[i]); totalShares > 100 {
			return Error("total shares exceed 100")
		}
		composerKeys[i] = ownersAfter[0]
	}
	if totalShares != 100 {
		return Error("total shares do not equal 100")
	}
	publisherId := spec.GetPublisherId(composition)
	if !EmptyStr(publisherId) {
		tx, err := ValidateUserId(publisherId)
		if err != nil {
			return err
		}
		if !ownersBefore[0].Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("publisher isn't ownerBefore")
		}
	} else {
		if !ownersBefore[0].Equals(composerKeys[0]) {
			return Error("first composer isn't ownerBefore")
		}
	}
	if n > 1 {
		if err := ValidateThreshold(composition, composerKeys, compositionTx); err != nil {
			return err
		}
	}
	return nil
}

func ProveComposer(challenge, composerId string, compositionId string, privkey crypto.PrivateKey) (crypto.Signature, error) {
	tx, err := ValidateCompositionId(compositionId)
	if err != nil {
		return nil, err
	}
	composers := spec.GetComposers(bigchain.GetTxAssetData(tx))
	for i, composer := range composers {
		if composerId == spec.GetId(composer) {
			pubkey := bigchain.DefaultTxOwnerAfter(tx, i)
			if !pubkey.Equals(privkey.Public()) {
				return nil, ErrInvalidKey
			}
			return privkey.Sign(Checksum256([]byte(challenge))), nil
		}
	}
	return nil, Error("couldn't match composer id")
}

func VerifyComposer(challenge, composerId, compositionId string, sig crypto.Signature) error {
	tx, err := ValidateCompositionId(compositionId)
	if err != nil {
		return err
	}
	composers := spec.GetComposers(bigchain.GetTxAssetData(tx))
	for i, composer := range composers {
		if composerId == spec.GetId(composer) {
			pubkey := bigchain.DefaultTxOwnerAfter(tx, i)
			if !pubkey.Verify(Checksum256([]byte(challenge)), sig) {
				return ErrInvalidSignature
			}
			return nil
		}
	}
	return Error("couldn't match composer id")
}

func BuildRightTransferTx(consumeId string, recipientId string, recipientKey crypto.PublicKey, rightToId, senderId string, senderKey crypto.PublicKey, transferAmount int) (Data, []string, error) {
	tx, err := bigchain.HttpGetTx(consumeId)
	if err != nil {
		return nil, nil, err
	}
	outputs := bigchain.GetTxOutputs(tx)
	// rightTo already validated..
	// check inputs, outputs, owners if consume id different
	if consumeId != rightToId {
		if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
			return nil, nil, Error("expected TRANSFER tx")
		}
		inputs := bigchain.GetTxInputs(tx)
		if len(inputs) != 1 {
			return nil, nil, Error("inputs should be 1")
		}
		ownersBefore := bigchain.GetInputOwnersBefore(inputs[0])
		if len(ownersBefore) != 1 {
			return nil, nil, Error("should be 1 ownerBefore")
		}
		if len(outputs) != 1 && len(outputs) != 2 {
			return nil, nil, Error("should be 1 or 2 outputs")
		}
		if rightToId != bigchain.GetTxAssetId(tx) {
			return nil, nil, Error("TRANSFER tx doesn't link to " + rightToId)
		}
	}
	for idx, output := range outputs {
		ownersAfter := bigchain.GetOutputOwnersAfter(output)
		if consumeId != rightToId {
			if len(ownersAfter) != 1 {
				return nil, nil, Error("should be 1 ownerAfter")
			}
		}
		if senderKey.Equals(ownersAfter[0]) {
			totalAmount := bigchain.GetOutputAmount(output)
			keepAmount := totalAmount - transferAmount
			if keepAmount == 0 {
				tx, err := bigchain.IndividualTransferTx(transferAmount, rightToId, consumeId, idx, recipientKey, senderKey)
				if err != nil {
					return nil, nil, err
				}
				return tx, []string{recipientId}, nil
			}
			if keepAmount > 0 {
				tx, err := bigchain.DivisibleTransferTx([]int{keepAmount, transferAmount}, rightToId, consumeId, idx, []crypto.PublicKey{senderKey, recipientKey}, senderKey)
				if err != nil {
					return nil, nil, err
				}
				return tx, []string{senderId, recipientId}, nil
			}
			return nil, nil, Error("sender cannot transfer that many shares")
		}
	}
	return nil, nil, Error("sender not ownerAfter of consume tx")
}

func BuildRightTx(percentShares int, prevRightId string, privkey crypto.PrivateKey, recipientId, rightToId, senderId string, senderKey crypto.PublicKey) (Data, error) {
	tx, err := ValidateUserId(recipientId)
	if err != nil {
		return nil, err
	}
	recipientKey := bigchain.DefaultTxOwnerBefore(tx)
	tx, err = bigchain.HttpGetTx(rightToId)
	if err != nil {
		return nil, err
	}
	rightToType := spec.GetType(bigchain.GetTxAssetData(tx))
	if rightToType == "MusicComposition" {
		err = ValidateCompositionTx(tx)
	} else if rightToType == "MusicRecording" {
		err = ValidateRecordingTx(tx)
	} else {
		err = Error("expected MusicComposition or MusicRecording; got " + rightToType)
	}
	if err != nil {
		return nil, err
	}
	consumeId := rightToId
	if !EmptyStr(prevRightId) {
		tx, _, err = CheckRightHolder(senderId, prevRightId)
		if err != nil {
			return nil, err
		}
		consumeId = spec.GetTransferId(bigchain.GetTxAssetData(tx))
	}
	tx, rightHolderIds, err := BuildRightTransferTx(consumeId, recipientId, recipientKey, rightToId, senderId, senderKey, percentShares)
	if err != nil {
		return nil, err
	}
	bigchain.FulfillTx(tx, privkey)
	transferId, err := bigchain.HttpPostTx(tx)
	if err != nil {
		return nil, err
	}
	right, err := spec.NewRight(rightHolderIds, rightToId, transferId)
	if err != nil {
		return nil, err
	}
	if len(rightHolderIds) == 1 {
		return bigchain.IndividualCreateTx(1, right, recipientKey, senderKey)
	}
	return bigchain.MultipleOwnersCreateTx([]int{1, 1}, right, []crypto.PublicKey{senderKey, recipientKey}, senderKey)
}

func ValidateRightId(id string) (Data, error) {
	tx, err := bigchain.HttpGetTx(id)
	if err != nil {
		return nil, err
	}
	if err = ValidateRightTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateRightTx(tx Data) (err error) {
	right := bigchain.GetTxAssetData(tx)
	if err := schema.ValidateSchema(right, "right"); err != nil {
		return err
	}
	rightHolderIds := spec.GetRightHolderIds(right)
	n := len(rightHolderIds)
	if n != 1 && n != 2 {
		return Error("must be 1 or 2 right-holder ids")
	}
	inputs := bigchain.GetTxInputs(tx)
	if len(inputs) != 1 {
		return Error("should be 1 input")
	}
	ownersBefore := bigchain.GetInputOwnersBefore(inputs[0])
	if len(ownersBefore) != 1 {
		return Error("should be 1 ownerBefore")
	}
	outputs := bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return Error("different number of right outputs and right-holder ids")
	}
	var recipientKey crypto.PublicKey
	for i, rightHolderId := range rightHolderIds {
		tx, err = ValidateUserId(rightHolderId)
		if err != nil {
			return err
		}
		ownersAfter := bigchain.GetOutputOwnersAfter(outputs[i])
		if len(ownersAfter) != 1 {
			return Error("should be 1 ownerAfter")
		}
		rightHolderKey := bigchain.DefaultTxOwnerBefore(tx)
		if !ownersAfter[0].Equals(rightHolderKey) {
			return Error("right-holder is not ownerAfter")
		}
		if ownersBefore[0].Equals(rightHolderKey) {
			if i == 1 || n == 1 {
				return Error("ownerBefore cannot be only/second right-holder")
			}
		} else {
			if i == 0 && n == 2 {
				return Error("ownerBefore isn't first right-holder")
			}
			recipientKey = rightHolderKey
		}
	}
	rightToId := spec.GetRightToId(right)
	tx, err = bigchain.HttpGetTx(rightToId)
	if err != nil {
		return err
	}
	rightToType := spec.GetType(bigchain.GetTxAssetData(tx))
	if rightToType == "MusicComposition" {
		err = ValidateCompositionTx(tx)
	} else if rightToType == "MusicRecording" {
		err = ValidateRecordingTx(tx)
	} else {
		err = Error("expected MusicComposition or MusicRecording; got " + rightToType)
	}
	if err != nil {
		return err
	}
	ownerBefore := ownersBefore[0]
	transferId := spec.GetTransferId(right)
	tx, err = bigchain.HttpGetTx(transferId)
	if err != nil {
		return err
	}
	if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
		return Error("expected TRANSFER")
	}
	inputs = bigchain.GetTxInputs(tx)
	if len(inputs) != 1 {
		return Error("inputs should be 1")
	}
	ownersBefore = bigchain.GetInputOwnersBefore(inputs[0])
	if len(ownersBefore) != 1 {
		return Error("should be 1 ownerBefore")
	}
	if !ownerBefore.Equals(ownersBefore[0]) {
		return Error("right ownerBefore isn't TRANSFER ownerBefore")
	}
	outputs = bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return Error("different number of TRANSFER tx outputs and right-holder ids")
	}
	idx := 0
	if n == 2 {
		ownersAfter := bigchain.GetOutputOwnersAfter(outputs[0])
		if len(ownersAfter) != 1 {
			return Error("should be 1 ownerAfter")
		}
		if !ownerBefore.Equals(ownersAfter[0]) {
			return Error("ownerBefore isn't TRANSFER ownerAfter")
		}
		senderShares := bigchain.GetOutputAmount(outputs[0])
		if senderShares <= 0 || senderShares >= 100 {
			return Error("sender shares must be greater than 0 and less than 100")
		}
		idx = 1
	}
	ownersAfter := bigchain.GetOutputOwnersAfter(outputs[idx])
	if len(ownersAfter) != 1 {
		return Error("should be 1 ownerAfter")
	}
	if !recipientKey.Equals(ownersAfter[0]) {
		return Error("right recipient isn't ownerAfter of TRANSFER")
	}
	recipientShares := bigchain.GetOutputAmount(outputs[idx])
	if recipientShares <= 0 || recipientShares > 100 {
		return Error("recipient shares must be greater than 0 and less than/equal to 100")
	}
	if rightToId != bigchain.GetTxAssetId(tx) {
		return Error("TRANSFER tx doesn't link to " + rightToType)
	}
	return nil
}

func CheckRightHolder(rightHolderId, rightId string) (Data, crypto.PublicKey, error) {
	tx, err := ValidateRightId(rightId)
	if err != nil {
		return nil, nil, err
	}
	right := bigchain.GetTxAssetData(tx)
	rightHolderIds := spec.GetRightHolderIds(right)
	for i := range rightHolderIds {
		if rightHolderId == rightHolderIds[i] {
			rightHolderKey := bigchain.DefaultTxOwnerAfter(tx, i)
			transferId := spec.GetTransferId(right)
			txs, err := bigchain.HttpGetTransfers(spec.GetRightToId(right))
			if err != nil {
				return nil, nil, err
			}
			for _, tx := range txs {
				consume := bigchain.DefaultTxConsume(tx)
				if transferId == consume.GetStr("txid") {
					if i == consume.GetInt("output") {
						return nil, nil, Error("TRANSFER tx output has been spent")
					}
				}
			}
			return tx, rightHolderKey, nil
		}
	}
	return nil, nil, Error("couldn't match right-holder id")
}

func ProveRightHolder(challenge string, privkey crypto.PrivateKey, rightHolderId, rightId string) (crypto.Signature, error) {
	_, rightHolderKey, err := CheckRightHolder(rightHolderId, rightId)
	if err != nil {
		return nil, err
	}
	if !rightHolderKey.Equals(privkey.Public()) {
		return nil, ErrInvalidKey
	}
	return privkey.Sign(Checksum256([]byte(challenge))), nil
}

func VerifyRightHolder(challenge string, rightHolderId, rightId string, sig crypto.Signature) error {
	_, rightHolderKey, err := CheckRightHolder(rightHolderId, rightId)
	if err != nil {
		return err
	}
	if !rightHolderKey.Verify(Checksum256([]byte(challenge)), sig) {
		return ErrInvalidSignature
	}
	return nil
}

func ValidateLicenseId(id string) (Data, error) {
	tx, err := bigchain.HttpGetTx(id)
	if err != nil {
		return nil, err
	}
	if err = ValidateLicenseTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func BuildLicenseTx(license Data, licenserKey crypto.PublicKey) (Data, error) {
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	n := len(licenseHolderIds)
	amounts := make([]int, n)
	licenseHolderKeys := make([]crypto.PublicKey, n)
	licenserId := spec.GetLicenserId(license)
	for i, licenseHolderId := range licenseHolderIds {
		if licenserId == licenseHolderId {
			return nil, Error("licenser cannot be license-holder")
		}
		tx, err := ValidateUserId(licenseHolderId)
		if err != nil {
			return nil, err
		}
		amounts[i] = 1
		licenseHolderKeys[i] = bigchain.DefaultTxOwnerBefore(tx)
	}
	licenseFor := spec.GetLicenseFor(license)
OUTER:
	for i := range licenseFor {
		licenseForId := spec.GetId(licenseFor[i])
		tx, err := bigchain.HttpGetTx(licenseForId)
		if err != nil {
			return nil, err
		}
		licensed := bigchain.GetTxAssetData(tx)
		licensedType := spec.GetType(licensed)
		if licensedType == "MusicComposition" {
			err = ValidateCompositionTx(tx)
		} else if licensedType == "MusicRecording" {
			err = ValidateRecordingTx(tx)
		} else {
			err = Error("expected MusicComposition or MusicRecording; got " + licensedType)
		}
		if err != nil {
			return nil, err
		}
		rightId := spec.GetRightId(licenseFor[i])
		if !EmptyStr(rightId) {
			tx, _, err = CheckRightHolder(licenserId, rightId)
			if err != nil {
				return nil, err
			}
			right := bigchain.GetTxAssetData(tx)
			if licenseForId != spec.GetRightToId(right) {
				return nil, Error("right doesn't link to licensed composition/recording id")
			}
			rightHolderIds := spec.GetRightHolderIds(right)
			for _, rightHolderId := range rightHolderIds {
				if licenserId == rightHolderId {
					continue OUTER
				}
			}
		} else {
			if licensedType == "MusicComposition" {
				composers := spec.GetComposers(licensed)
				for _, composer := range composers {
					if licenserId != spec.GetId(composer) {
						continue OUTER
					}
				}
			}
			if licensedType == "MusicRecording" {
				artists := spec.GetArtists(licensed)
				for _, artist := range artists {
					if licenserId != spec.GetId(artist) {
						continue OUTER
					}
				}
			}
		}
		return nil, Error("licenser isn't artist/composer or right-holder")
	}
	if n == 1 {
		return bigchain.IndividualCreateTx(amounts[0], license, licenseHolderKeys[0], licenserKey)
	}
	return bigchain.MultipleOwnersCreateTx(amounts, license, licenseHolderKeys, licenserKey)
}

func ValidateLicenseTx(tx Data) (err error) {
	license := bigchain.GetTxAssetData(tx)
	if err := schema.ValidateSchema(license, "license"); err != nil {
		return err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	n := len(licenseHolderIds)
	licenserId := spec.GetLicenserId(license)
	inputs := bigchain.GetTxInputs(tx)
	if len(inputs) != 1 {
		return Error("should be 1 input")
	}
	ownersBefore := bigchain.GetInputOwnersBefore(inputs[0])
	if len(ownersBefore) != 1 {
		return Error("should be 1 ownerBefore")
	}
	outputs := bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return Error("different number of license-holders and outputs")
	}
	for i, licenseHolderId := range licenseHolderIds {
		if licenserId == licenseHolderId {
			return Error("licenser cannot be license-holder")
		}
		tx, err = ValidateUserId(licenseHolderId)
		if err != nil {
			return err
		}
		ownersAfter := bigchain.GetOutputOwnersAfter(outputs[i])
		if len(ownersAfter) != 1 {
			return Error("should be 1 ownerAfter")
		}
		if !ownersAfter[0].Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("license-holder is not ownerAfter")
		}
	}
	tx, err = ValidateUserId(licenserId)
	if err != nil {
		return err
	}
	if !ownersBefore[0].Equals(bigchain.DefaultTxOwnerBefore(tx)) {
		return Error("licenser is not ownerBefore")
	}
	licenseFor := spec.GetLicenseFor(license)
OUTER:
	for i := range licenseFor {
		licenseForId := spec.GetId(licenseFor[i])
		tx, err = bigchain.HttpGetTx(licenseForId)
		if err != nil {
			return err
		}
		licensed := bigchain.GetTxAssetData(tx)
		licensedType := spec.GetType(licensed)
		if licensedType == "MusicComposition" {
			err = ValidateCompositionTx(tx)
		} else if licensedType == "MusicRecording" {
			err = ValidateRecordingTx(tx)
		} else {
			err = Error("expected MusicComposition or MusicRecording; got " + licensedType)
		}
		if err != nil {
			return err
		}
		rightId := spec.GetRightId(licenseFor[i])
		if !EmptyStr(rightId) {
			tx, _, err = CheckRightHolder(licenserId, rightId)
			if err != nil {
				return err
			}
			right := bigchain.GetTxAssetData(tx)
			if licenseForId != spec.GetRightToId(right) {
				return Error("right doesn't link to licensed composition/recording id")
			}
			rightHolderIds := spec.GetRightHolderIds(right)
			for _, rightHolderId := range rightHolderIds {
				if licenserId == rightHolderId {
					continue OUTER
				}
			}
		} else {
			if licensedType == "MusicComposition" {
				composers := spec.GetComposers(licensed)
				for _, composer := range composers {
					if licenserId != spec.GetId(composer) {
						continue OUTER
					}
				}
			}
			if licensedType == "MusicRecording" {
				artists := spec.GetArtists(licensed)
				for _, artist := range artists {
					if licenserId != spec.GetId(artist) {
						continue OUTER
					}
				}
			}
		}
		return Error("licenser isn't artist/composer or right-holder")
	}
	dateFrom, err := ParseDate(spec.GetValidFrom(license))
	if err != nil {
		return err
	}
	dateThrough, err := ParseDate(spec.GetValidThrough(license))
	if err != nil {
		return err
	}
	if !dateThrough.After(dateFrom) {
		return Error("Invalid license timeframe")
	}
	today := Today()
	if dateFrom.After(today) {
		return Error("License isn't yet valid")
	}
	if dateThrough.Before(today) {
		return Error("License is no longer valid")
	}
	return nil
}

func ProveLicenseHolder(challenge, licenseHolderId, licenseId string, privkey crypto.PrivateKey) (crypto.Signature, error) {
	tx, err := ValidateLicenseId(licenseId)
	if err != nil {
		return nil, err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(bigchain.GetTxAssetData(tx))
	for i := range licenseHolderIds {
		if licenseHolderId == licenseHolderIds[i] {
			tx, err := bigchain.HttpGetTx(licenseHolderId)
			if err != nil {
				return nil, err
			}
			licenseHolderKey := bigchain.DefaultTxOwnerBefore(tx)
			if !licenseHolderKey.Equals(privkey.Public()) {
				return nil, ErrInvalidKey
			}
			return privkey.Sign(Checksum256([]byte(challenge))), nil
		}
	}
	return nil, Error("couldn't match license-holder id")
}

func VerifyLicenseHolder(challenge, licenseHolderId, licenseId string, sig crypto.Signature) error {
	tx, err := ValidateLicenseId(licenseId)
	if err != nil {
		return err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(bigchain.GetTxAssetData(tx))
	for i := range licenseHolderIds {
		if licenseHolderId == licenseHolderIds[i] {
			tx, err := bigchain.HttpGetTx(licenseHolderId)
			if err != nil {
				return err
			}
			licenseHolderKey := bigchain.DefaultTxOwnerBefore(tx)
			if !licenseHolderKey.Verify(Checksum256([]byte(challenge)), sig) {
				return ErrInvalidSignature
			}
			return nil
		}
	}
	return Error("couldn't match license-holder id")
}

func ValidateRecordingId(id string) (Data, error) {
	tx, err := bigchain.HttpGetTx(id)
	if err != nil {
		return nil, err
	}
	if err = ValidateRecordingTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func BuildRecordingTx(recording Data, signatures []string, splits []int) (Data, error) {
	artists := spec.GetArtists(recording)
	n := len(artists)
	if n == 0 {
		return nil, Error("no artists")
	}
	if n > 1 {
		if signatures != nil {
			if n != len(signatures) {
				return nil, Error("different number of artists and signatures")
			}
		}
		if n != len(splits) {
			return nil, Error("different number of artists and splits")
		}
	}
	recordingOf := spec.GetRecordingOf(recording)
	compositionId := spec.GetId(recordingOf)
	tx, err := ValidateCompositionId(compositionId)
	if err != nil {
		return nil, err
	}
	composition := bigchain.GetTxAssetData(tx)
	var licenseHolderIds []string
	licenseId := spec.GetLicenseId(recordingOf)
	if !EmptyStr(licenseId) {
		tx, err = ValidateLicenseId(licenseId)
		if err != nil {
			return nil, err
		}
		license := bigchain.GetTxAssetData(tx)
		licenseFor := spec.GetLicenseFor(license)
		for i := range licenseFor {
			if compositionId == spec.GetId(licenseFor[i]) {
				licenseHolderIds = spec.GetLicenseHolderIds(license)
				goto NEXT
			}
		}
		return nil, Error("license doesn't link to composition")
	}
NEXT:
	artistKeys := make([]crypto.PublicKey, n)
	composers := spec.GetComposers(composition)
	totalShares := 0
OUTER:
	for i, artist := range artists {
		// TODO: check for repeat pubkeys
		artistId := spec.GetId(artist)
		tx, err = ValidateUserId(artistId)
		if err != nil {
			return nil, err
		}
		artistKeys[i] = bigchain.DefaultTxOwnerBefore(tx)
		if n > 1 {
			if totalShares += splits[i]; totalShares > 100 {
				return nil, Error("total shares exceed 100")
			}
		}
		for j, composer := range composers {
			if artistId == spec.GetId(composer) {
				composers = append(composers[:j], composers[j+1:]...)
				continue OUTER
			}
		}
		for j, licenseHolderId := range licenseHolderIds {
			if artistId == licenseHolderId {
				licenseHolderIds = append(licenseHolderIds[:j], licenseHolderIds[j+1:]...)
				continue OUTER
			}
		}
		return nil, Error("artist isn't composer/doesn't have mechanical")
	}
	if n > 1 {
		if totalShares != 100 {
			return nil, Error("total shares do not equal 100")
		}
	}
	recordLabelId := spec.GetRecordLabelId(recording)
	senderKey := artistKeys[0]
	if !EmptyStr(recordLabelId) {
		tx, err = ValidateUserId(recordLabelId)
		if err != nil {
			return nil, err
		}
		for i, licenseHolderId := range licenseHolderIds {
			if recordLabelId == licenseHolderId {
				licenseHolderIds = append(licenseHolderIds[:i], licenseHolderIds[i+1:]...)
				senderKey = bigchain.DefaultTxOwnerBefore(tx)
				goto END
			}
		}
		return nil, Error("record label doesn't have mechanical")
	}
END:
	if n == 1 {
		return bigchain.IndividualCreateTx(100, recording, artistKeys[0], senderKey)
	}
	tx, err = bigchain.MultipleOwnersCreateTx(splits, recording, artistKeys, senderKey)
	if err != nil {
		return nil, err
	}
	if signatures != nil {
		if err := SetThreshold(recording, artistKeys, signatures, tx); err != nil {
			return nil, err
		}
		tx, err = bigchain.MultipleOwnersCreateTx(splits, recording, artistKeys, senderKey)
		if err != nil {
			return nil, err
		}
	}
	return tx, nil
}

func ValidateRecordingTx(recordingTx Data) (err error) {
	recording := bigchain.GetTxAssetData(recordingTx)
	if err := schema.ValidateSchema(recording, "recording"); err != nil {
		return err
	}
	artists := spec.GetArtists(recording)
	n := len(artists)
	inputs := bigchain.GetTxInputs(recordingTx)
	if len(inputs) != 1 {
		return Error("should be 1 input")
	}
	ownersBefore := bigchain.GetInputOwnersBefore(inputs[0])
	if len(ownersBefore) != 1 {
		return Error("should be 1 ownerBefore")
	}
	outputs := bigchain.GetTxOutputs(recordingTx)
	if n != len(outputs) {
		return Error("different number of outputs and artists")
	}
	recordingOf := spec.GetRecordingOf(recording)
	compositionId := spec.GetId(recordingOf)
	composition, err := ValidateCompositionId(compositionId)
	if err != nil {
		return err
	}
	var licenseHolderIds []string
	licenseId := spec.GetLicenseId(recordingOf)
	if !EmptyStr(licenseId) {
		tx, err := ValidateLicenseId(licenseId)
		if err != nil {
			return err
		}
		license := bigchain.GetTxAssetData(tx)
		licenseFor := spec.GetLicenseFor(license)
		for i := range licenseFor {
			if compositionId == spec.GetId(licenseFor[i]) {
				licenseHolderIds = spec.GetLicenseHolderIds(license)
				goto NEXT
			}
		}
		return Error("license doesn't link to composition")
	}
NEXT:
	artistKeys := make([]crypto.PublicKey, n)
	composers := spec.GetComposers(composition)
	totalShares := 0
OUTER:
	for i, artist := range artists {
		// TODO: check for repeat pubkeys
		artistId := spec.GetId(artist)
		tx, err := ValidateUserId(artistId)
		if err != nil {
			return err
		}
		ownersAfter := bigchain.GetOutputOwnersAfter(outputs[i])
		if len(ownersAfter) != 1 {
			return Error("should be 1 ownerAfter")
		}
		if !ownersAfter[0].Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("artist isn't ownerAfter")
		}
		if totalShares += bigchain.GetOutputAmount(outputs[i]); totalShares > 100 {
			return Error("total shares exceed 100")
		}
		artistKeys[i] = ownersAfter[0]
		for j, composer := range composers {
			if artistId == spec.GetId(composer) {
				composers = append(composers[:j], composers[j+1:]...)
				continue OUTER
			}
		}
		for j, licenseHolderId := range licenseHolderIds {
			if artistId == licenseHolderId {
				licenseHolderIds = append(licenseHolderIds[:j], licenseHolderIds[j+1:]...)
				continue OUTER
			}
		}
		return Error("artist isn't composer/doesn't have mechanical")
	}
	if totalShares != 100 {
		return Error("total shares do not equal 100")
	}
	recordLabelId := spec.GetRecordLabelId(recording)
	if !EmptyStr(recordLabelId) {
		tx, err := ValidateUserId(recordLabelId)
		if err != nil {
			return err
		}
		if !ownersBefore[0].Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("record label isn't ownerBefore")
		}
		for i, licenseHolderId := range licenseHolderIds {
			if recordLabelId == licenseHolderId {
				licenseHolderIds = append(licenseHolderIds[:i], licenseHolderIds[i+1:]...)
				goto END
			}
		}
		return Error("record label doesn't have mechanical")
	} else {
		if !ownersBefore[0].Equals(artistKeys[0]) {
			return Error("first artist isn't ownerBefore")
		}
	}
END:
	if n > 1 {
		if err = ValidateThreshold(recording, artistKeys, recordingTx); err != nil {
			return err
		}
	}
	return nil
}

func ProveArtist(artistId, challenge string, privkey crypto.PrivateKey, recordingId string) (crypto.Signature, error) {
	tx, err := ValidateRecordingId(recordingId)
	if err != nil {
		return nil, err
	}
	artists := spec.GetArtists(bigchain.GetTxAssetData(tx))
	for i, artist := range artists {
		if artistId == spec.GetId(artist) {
			pubkey := bigchain.DefaultTxOwnerAfter(tx, i)
			if !pubkey.Equals(privkey.Public()) {
				return nil, ErrInvalidKey
			}
			return privkey.Sign(Checksum256([]byte(challenge))), nil
		}
	}
	return nil, Error("couldn't match artist id")
}

func VerifyArtist(artistId, challenge string, recordingId string, sig crypto.Signature) error {
	tx, err := ValidateRecordingId(recordingId)
	if err != nil {
		return err
	}
	artists := spec.GetArtists(bigchain.GetTxAssetData(tx))
	for i, artist := range artists {
		if artistId == spec.GetId(artist) {
			pubkey := bigchain.DefaultTxOwnerAfter(tx, i)
			if !pubkey.Verify(Checksum256([]byte(challenge)), sig) {
				return ErrInvalidSignature
			}
			return nil
		}
	}
	return Error("couldn't match artist id")
}
