package linked_data

import (
	"github.com/Envoke-org/envoke-api/bigchain"
	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/schema"
	"github.com/Envoke-org/envoke-api/spec"
)

func CheckTxOwnerBefore(tx Data) (crypto.PublicKey, error) {
	ownersBefore, err := CheckTxOwnersBefore(tx, 1)
	if err != nil {
		return nil, err
	}
	return ownersBefore[0], nil
}

func CheckTxOwnersBefore(tx Data, n int) ([]crypto.PublicKey, error) {
	inputs := bigchain.GetTxInputs(tx)
	if len(inputs) != 1 {
		return nil, Error("should be 1 input")
	}
	ownersBefore := bigchain.GetInputOwnersBefore(inputs[0])
	if len(ownersBefore) != n {
		return nil, Errorf("should be %d ownersBefore", n)
	}
	return ownersBefore, nil
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
	ownerBefore, err := CheckTxOwnerBefore(tx)
	if err != nil {
		return err
	}
	outputs := bigchain.GetTxOutputs(tx)
	if len(outputs) != 1 {
		return Error("should be 1 output")
	}
	ownerAfter, err := CheckOutputOwnerAfter(outputs[0])
	if err != nil {
		return err
	}
	if !ownerAfter.Equals(ownerBefore) {
		return Error("user has different ownerAfter and ownerBefore")
	}
	return nil
}

func AssembleCompositionTx(composition Data, privkey crypto.PrivateKey, signatures []string, splits []int) (Data, error) {
	composers := spec.GetComposers(composition)
	n := len(composers)
	if n == 0 {
		return nil, Error("no composers")
	}
	publishers := spec.GetPublishers(composition)
	n += len(publishers)
	if signatures != nil {
		if n != len(signatures) {
			return nil, Error("different number of composers/publishers and signatures")
		}
	}
	if n != len(splits) {
		return nil, Error("different number of composers/publishers and splits")
	}
	parties := append(composers, publishers...)
	pubkeys := make([]crypto.PublicKey, n)
	totalShares := 0
	for i, party := range parties {
		partyId := spec.GetId(party)
		tx, err := ValidateUserId(partyId)
		if err != nil {
			return nil, err
		}
		pubkeys[i] = bigchain.DefaultTxOwnerBefore(tx)
		if totalShares += splits[i]; totalShares > 100 {
			return nil, Error("total shares exceed 100")
		}
	}
	if totalShares != 100 {
		return nil, Error("total shares do not equal 100")
	}
	tx, err := bigchain.CreateTx(splits, composition, pubkeys, pubkeys)
	if err != nil {
		return nil, err
	}
	if n == 1 {
		if err = bigchain.IndividualFulfillTx(tx, privkey); err != nil {
			return nil, err
		}
	}
	if signatures != nil {
		if err = bigchain.MultipleFulfillTx(tx, pubkeys, signatures); err != nil {
			return nil, err
		}
	}
	return tx, nil
}

func ValidateCompositionId(compositionId string) (Data, error) {
	tx, err := bigchain.HttpGetTx(compositionId)
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
	if n == 0 {
		return Error("no composers")
	}
	publishers := spec.GetPublishers(composition)
	n += len(publishers)
	ownersBefore, err := CheckTxOwnersBefore(compositionTx, n)
	if err != nil {
		return err
	}
	outputs := bigchain.GetTxOutputs(compositionTx)
	if n != len(outputs) {
		return Error("different number of composers/publishers and outputs")
	}
	parties := append(composers, publishers...)
	totalShares := 0
	for i, party := range parties {
		tx, err := ValidateUserId(spec.GetId(party))
		if err != nil {
			return err
		}
		if !ownersBefore[i].Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("composer/publisher isn't tx ownerBefore")
		}
		ownerAfter, err := CheckOutputOwnerAfter(outputs[i])
		if err != nil {
			return err
		}
		if !ownerAfter.Equals(ownersBefore[i]) {
			return Error("composer/publisher isn't output ownerAfter")
		}
		if totalShares += bigchain.GetOutputAmount(outputs[i]); totalShares > 100 {
			return Error("total shares exceed 100")
		}
	}
	if totalShares != 100 {
		return Error("total shares do not equal 100")
	}
	return nil
}

func CheckComposer(composerId, compositionId string) (Data, crypto.PublicKey, error) {
	tx, err := ValidateCompositionId(compositionId)
	if err != nil {
		return nil, nil, err
	}
	composers := spec.GetComposers(bigchain.GetTxAssetData(tx))
	for i, composer := range composers {
		if composerId == spec.GetId(composer) {
			return tx, bigchain.DefaultTxOwnerAfter(tx, i), nil
		}
	}
	return nil, nil, Error("couldn't match composer id")
}

func ProveComposer(challenge, composerId string, compositionId string, privkey crypto.PrivateKey) (crypto.Signature, error) {
	_, pubkey, err := CheckComposer(composerId, compositionId)
	if err != nil {
		return nil, err
	}
	if !pubkey.Equals(privkey.Public()) {
		return nil, ErrInvalidKey
	}
	return privkey.Sign(Checksum256([]byte(challenge))), nil
}

func VerifyComposer(challenge, composerId, compositionId string, sig crypto.Signature) error {
	_, pubkey, err := CheckComposer(composerId, compositionId)
	if err != nil {
		return err
	}
	if !pubkey.Verify(Checksum256([]byte(challenge)), sig) {
		return ErrInvalidSignature
	}
	return nil
}

func CheckPublisher(compositionId, publisherId string) (Data, crypto.PublicKey, error) {
	tx, err := ValidateCompositionId(compositionId)
	if err != nil {
		return nil, nil, err
	}
	publishers := spec.GetPublishers(bigchain.GetTxAssetData(tx))
	for i, publisher := range publishers {
		if publisherId == spec.GetId(publisher) {
			return tx, bigchain.DefaultTxOwnerAfter(tx, i), nil
		}
	}
	return nil, nil, Error("couldn't match publisher id")
}

func ProvePublisher(challenge, compositionId string, privkey crypto.PrivateKey, publisherId string) (crypto.Signature, error) {
	_, pubkey, err := CheckPublisher(compositionId, publisherId)
	if err != nil {
		return nil, err
	}
	if !pubkey.Equals(privkey.Public()) {
		return nil, ErrInvalidKey
	}
	return privkey.Sign(Checksum256([]byte(challenge))), nil
}

func VerifyPublisher(challenge, compositionId, publisherId string, sig crypto.Signature) error {
	_, pubkey, err := CheckPublisher(compositionId, publisherId)
	if err != nil {
		return err
	}
	if !pubkey.Verify(Checksum256([]byte(challenge)), sig) {
		return ErrInvalidSignature
	}
	return nil
}

func AssembleRightTransferTx(consumeId string, recipientId string, recipientKey crypto.PublicKey, rightToId, senderId string, senderKey crypto.PublicKey, transferAmount int) (Data, []string, error) {
	txIds, outputs, err := bigchain.HttpGetOutputs(senderKey, true)
	if err != nil {
		return nil, nil, err
	}
	var i int
	for i = range txIds {
		if consumeId == txIds[i] {
			goto NEXT
		}
	}
	return nil, nil, Error("sender doesn't have output in consume tx")
NEXT:
	tx, err := bigchain.HttpGetTx(consumeId)
	if err != nil {
		return nil, nil, err
	}
	if consumeId != rightToId {
		if err = ValidateTransferTx(tx); err != nil {
			return nil, nil, err
		}
		if rightToId != bigchain.GetTxAssetId(tx) {
			return nil, nil, Error("TRANSFER tx doesn't link to " + rightToId)
		}
	}
	output := bigchain.GetTxOutput(tx, outputs[i])
	totalAmount := bigchain.GetOutputAmount(output)
	keepAmount := totalAmount - transferAmount
	if keepAmount == 0 {
		tx, err := bigchain.TransferTx([]int{transferAmount}, rightToId, consumeId, outputs[i], []crypto.PublicKey{recipientKey}, []crypto.PublicKey{senderKey})
		if err != nil {
			return nil, nil, err
		}
		return tx, []string{recipientId}, nil
	}
	if keepAmount > 0 {
		tx, err := bigchain.TransferTx([]int{keepAmount, transferAmount}, rightToId, consumeId, outputs[i], []crypto.PublicKey{senderKey, recipientKey}, []crypto.PublicKey{senderKey})
		if err != nil {
			return nil, nil, err
		}
		return tx, []string{senderId, recipientId}, nil
	}
	return nil, nil, Error("sender cannot transfer that many shares")
}

func AssembleRightTx(percentShares int, prevRightId string, privkey crypto.PrivateKey, pubkey crypto.PublicKey, recipientId, rightToId, senderId string) (Data, error) {
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
		right := bigchain.GetTxAssetData(tx)
		if rightToId != spec.GetRightToId(right) {
			return nil, Error("right doesn't link to composition/recording")
		}
		consumeId = spec.GetTransferId(right)
	}
	tx, rightHolderIds, err := AssembleRightTransferTx(consumeId, recipientId, recipientKey, rightToId, senderId, pubkey, percentShares)
	if err != nil {
		return nil, err
	}
	if err = bigchain.IndividualFulfillTx(tx, privkey); err != nil {
		return nil, err
	}
	transferId, err := bigchain.HttpPostTx(tx)
	if err != nil {
		return nil, err
	}
	right, err := spec.NewRight(rightHolderIds, rightToId, transferId)
	if err != nil {
		return nil, err
	}
	if len(rightHolderIds) == 1 {
		tx, err = bigchain.CreateTx([]int{1}, right, []crypto.PublicKey{recipientKey}, []crypto.PublicKey{pubkey})
	} else {
		tx, err = bigchain.CreateTx([]int{1, 1}, right, []crypto.PublicKey{pubkey, recipientKey}, []crypto.PublicKey{pubkey})
	}
	if err != nil {
		return nil, err
	}
	if err = bigchain.IndividualFulfillTx(tx, privkey); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateRightId(rightId string) (Data, error) {
	tx, err := bigchain.HttpGetTx(rightId)
	if err != nil {
		return nil, err
	}
	if err = ValidateRightTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateTransferId(transferId string) (Data, error) {
	tx, err := bigchain.HttpGetTx(transferId)
	if err != nil {
		return nil, err
	}
	if err = ValidateTransferTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateTransferTx(tx Data) error {
	if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
		return Error("expected TRANSFER")
	}
	ownerBefore, err := CheckTxOwnerBefore(tx)
	if err != nil {
		return err
	}
	outputs := bigchain.GetTxOutputs(tx)
	n := len(outputs)
	if n != 1 && n != 2 {
		return Error("should be 1 or 2 outputs")
	}
	if n == 2 {
		ownerAfter, err := CheckOutputOwnerAfter(outputs[0])
		if err != nil {
			return err
		}
		if !ownerAfter.Equals(ownerBefore) {
			return Error("ownerBefore should be TRANSFER ownerAfter")
		}
		senderShares := bigchain.GetOutputAmount(outputs[0])
		if senderShares <= 0 || senderShares >= 100 {
			return Error("sender shares must be greater than 0 and less than 100")
		}
	}
	if _, err = CheckOutputOwnerAfter(outputs[n-1]); err != nil {
		return err
	}
	recipientShares := bigchain.GetOutputAmount(outputs[n-1])
	if recipientShares <= 0 || recipientShares > 100 {
		return Error("recipient shares must be greater than 0 and less than/equal to 100")
	}
	return nil
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
	ownerBefore, err := CheckTxOwnerBefore(tx)
	if err != nil {
		return err
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
		ownerAfter, err := CheckOutputOwnerAfter(outputs[i])
		if err != nil {
			return err
		}
		if !ownerAfter.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("right-holder is not ownerAfter")
		}
		if ownerAfter.Equals(ownerBefore) {
			if i == 1 || n == 1 {
				return Error("ownerBefore cannot be only/second right-holder")
			}
		} else {
			if i == 0 && n == 2 {
				return Error("ownerBefore isn't first right-holder")
			}
			recipientKey = ownerAfter
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
	tx, err = ValidateTransferId(spec.GetTransferId(right))
	if err != nil {
		return err
	}
	if !ownerBefore.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
		return Error("right ownerBefore isn't TRANSFER ownerBefore")
	}
	outputs = bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return Error("different number of right-holders and TRANSFER")
	}
	ownerAfter := bigchain.DefaultOutputOwnerAfter(outputs[n-1])
	if !ownerAfter.Equals(recipientKey) {
		return Error("right recipient isn't TRANSFER ownerAfter")
	}
	if rightToId != bigchain.GetTxAssetId(tx) {
		return Error("TRANSFER doesn't link to " + rightToType)
	}
	return nil
}

func CheckLicenseHolder(licenseHolderId, licenseId string) (Data, crypto.PublicKey, error) {
	tx, err := ValidateLicenseId(licenseId)
	if err != nil {
		return nil, nil, err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(bigchain.GetTxAssetData(tx))
	for i := range licenseHolderIds {
		if licenseHolderId == licenseHolderIds[i] {
			return tx, bigchain.DefaultTxOwnerAfter(tx, i), nil
		}
	}
	return nil, nil, Error("couldn't match license-holder id")
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
			pubkey := bigchain.DefaultTxOwnerAfter(tx, i)
			txIds, outputs, err := bigchain.HttpGetOutputs(pubkey, true)
			if err != nil {
				return nil, nil, err
			}
			transferId := spec.GetTransferId(right)
			for j, txId := range txIds {
				if transferId == txId {
					if i == outputs[j] {
						return tx, pubkey, nil
					}
					break
				}
			}
			return nil, nil, Error("right-holder doesn't have unspent TRANSFER output")
		}
	}
	return nil, nil, Error("couldn't match right-holder id")
}

func ProveRightHolder(challenge string, privkey crypto.PrivateKey, rightHolderId, rightId string) (crypto.Signature, error) {
	_, pubkey, err := CheckRightHolder(rightHolderId, rightId)
	if err != nil {
		return nil, err
	}
	if !pubkey.Equals(privkey.Public()) {
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

func ValidateLicenseId(licenseId string) (Data, error) {
	tx, err := bigchain.HttpGetTx(licenseId)
	if err != nil {
		return nil, err
	}
	if err = ValidateLicenseTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func AssembleLicenseTx(license Data, privkey crypto.PrivateKey, pubkey crypto.PublicKey) (Data, error) {
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	n := len(licenseHolderIds)
	amounts := make([]int, n)
	licenseForIds := spec.GetLicenseForIds(license)
	licenser := spec.GetLicenser(license)
	licenserId := spec.GetId(licenser)
	pubkeys := make([]crypto.PublicKey, n)
	rightIds := spec.GetRightIds(license)
	hasRights := len(licenseForIds) == len(rightIds)
	for i, licenseHolderId := range licenseHolderIds {
		if licenserId == licenseHolderId {
			return nil, Error("licenser cannot be license-holder")
		}
		tx, err := ValidateUserId(licenseHolderId)
		if err != nil {
			return nil, err
		}
		amounts[i] = 1
		pubkeys[i] = bigchain.DefaultTxOwnerBefore(tx)
	}
OUTER:
	for i, licenseForId := range licenseForIds {
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
		if hasRights {
			if !EmptyStr(rightIds[i]) {
				tx, _, err = CheckRightHolder(licenserId, rightIds[i])
				if err != nil {
					return nil, err
				}
				if licenseForId != spec.GetRightToId(bigchain.GetTxAssetData(tx)) {
					return nil, Error("license doesn't link to composition/recording")
				}
				continue OUTER
			}
		} else {
			txIds, _, err := bigchain.HttpGetOutputs(pubkey, true)
			if err != nil {
				return nil, err
			}
			for _, txId := range txIds {
				if txId == licenseForId {
					continue OUTER
				}
			}
		}
		return nil, Error("licenser isn't right-holder")
	}
	tx, err := bigchain.CreateTx(amounts, license, pubkeys, []crypto.PublicKey{pubkey})
	if err != nil {
		return nil, err
	}
	if err = bigchain.IndividualFulfillTx(tx, privkey); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateLicenseTx(tx Data) (err error) {
	license := bigchain.GetTxAssetData(tx)
	if err := schema.ValidateSchema(license, "license"); err != nil {
		return err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	n := len(licenseHolderIds)
	licenser := spec.GetLicenser(license)
	licenserId := spec.GetId(licenser)
	ownerBefore, err := CheckTxOwnerBefore(tx)
	if err != nil {
		return err
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
		ownerAfter, err := CheckOutputOwnerAfter(outputs[i])
		if err != nil {
			return err
		}
		if !ownerAfter.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("license-holder is not ownerAfter")
		}
	}
	tx, err = ValidateUserId(licenserId)
	if err != nil {
		return err
	}
	if !ownerBefore.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
		return Error("licenser is not ownerBefore")
	}
	licenseForIds := spec.GetLicenseForIds(license)
	rightIds := spec.GetRightIds(licenser)
	hasRights := len(licenseForIds) == len(rightIds)
OUTER:
	for i, licenseForId := range licenseForIds {
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
		if hasRights {
			if !EmptyStr(rightIds[i]) {
				tx, _, err = CheckRightHolder(licenserId, rightIds[i])
				if err != nil {
					return err
				}
				if licenseForId != spec.GetRightToId(bigchain.GetTxAssetData(tx)) {
					return err
				}
				continue OUTER
			}
		} else {
			txIds, _, err := bigchain.HttpGetOutputs(ownerBefore, true)
			if err != nil {
				return err
			}
			for _, txId := range txIds {
				if txId == licenseForId {
					continue OUTER
				}
			}
		}
		return Error("licenser isn't right-holder")
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
	_, pubkey, err := CheckLicenseHolder(licenseHolderId, licenseId)
	if err != nil {
		return nil, err
	}
	if !pubkey.Equals(privkey.Public()) {
		return nil, ErrInvalidKey
	}
	return privkey.Sign(Checksum256([]byte(challenge))), nil
}

func VerifyLicenseHolder(challenge, licenseHolderId, licenseId string, sig crypto.Signature) error {
	_, licenseHolderKey, err := CheckLicenseHolder(licenseHolderId, licenseId)
	if err != nil {
		return err
	}
	if !licenseHolderKey.Verify(Checksum256([]byte(challenge)), sig) {
		return ErrInvalidSignature
	}
	return nil
}

func ValidateRecordingId(recordingId string) (Data, error) {
	tx, err := bigchain.HttpGetTx(recordingId)
	if err != nil {
		return nil, err
	}
	if err = ValidateRecordingTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func AssembleRecordingTx(privkey crypto.PrivateKey, recording Data, signatures []string, splits []int) (Data, error) {
	artists := spec.GetArtists(recording)
	n := len(artists)
	if n == 0 {
		return nil, Error("no artists")
	}
	recordLabels := spec.GetRecordLabels(recording)
	n += len(recordLabels)
	if signatures != nil {
		if n != len(signatures) {
			return nil, Error("different number of artists/record labels and signatures")
		}
	}
	if n != len(splits) {
		return nil, Error("different number of artists/record labels and splits")
	}
	compositionId := spec.GetRecordingOfId(recording)
	tx, err := ValidateCompositionId(compositionId)
	if err != nil {
		return nil, err
	}
	licenseHolders := make(map[string][]string)
	parties := append(artists, recordLabels...)
	pubkeys := make([]crypto.PublicKey, n)
	rightHolders := make(map[string][]string)
	totalShares := 0
OUTER:
	for i, party := range parties {
		partyId := spec.GetId(party)
		tx, err = ValidateUserId(partyId)
		if err != nil {
			return nil, err
		}
		pubkeys[i] = bigchain.DefaultTxOwnerBefore(tx)
		if totalShares += splits[i]; totalShares > 100 {
			return nil, Error("total shares exceed 100")
		}
		licenseId := spec.GetLicenseId(party)
		if !EmptyStr(licenseId) {
			licenseHolderIds, ok := licenseHolders[licenseId]
			if !ok {
				tx, err = ValidateLicenseId(licenseId)
				if err != nil {
					return nil, err
				}
				license := bigchain.GetTxAssetData(tx)
				for _, licenseForId := range spec.GetLicenseForIds(license) {
					if compositionId == licenseForId {
						licenseHolderIds = spec.GetLicenseHolderIds(license)
						goto NEXT
					}
				}
				return nil, Error("license does not link to composition")
			}
		NEXT:
			for i, licenseHolderId := range licenseHolderIds {
				if licenseHolderId == partyId {
					licenseHolderIds = append(licenseHolderIds[:i], licenseHolderIds[i+1:]...)
					licenseHolders[licenseId] = licenseHolderIds
					continue OUTER
				}
			}
			return nil, Error("artist/record label doesn't have mechanical")
		}
		rightId := spec.GetRightId(party)
		if !EmptyStr(rightId) {
			rightHolderIds, ok := rightHolders[rightId]
			if !ok {
				tx, _, err := CheckRightHolder(partyId, rightId)
				if err != nil {
					return nil, err
				}
				right := bigchain.GetTxAssetData(tx)
				if compositionId != spec.GetRightToId(right) {
					return nil, Error("right doesn't link to composition")
				}
				rightHolderIds = spec.GetRightHolderIds(right)
			}
			for i, rightHolderId := range rightHolderIds {
				if rightHolderId == partyId {
					rightHolderIds = append(rightHolderIds[:i], rightHolderIds[i+1:]...)
					rightHolders[rightId] = rightHolderIds
					continue OUTER
				}
			}
			return nil, Error("artist/record label isn't right-holder")
		}
		txIds, _, err := bigchain.HttpGetOutputs(pubkeys[i], true)
		if err != nil {
			return nil, err
		}
		for _, txId := range txIds {
			if compositionId == txId {
				continue OUTER
			}
		}
		return nil, Error("artist/record label isn't composer/publisher")
	}
	if totalShares != 100 {
		return nil, Error("total shares do not equal 100")
	}
	tx, err = bigchain.CreateTx(splits, recording, pubkeys, pubkeys)
	if err != nil {
		return nil, err
	}
	if n == 1 {
		if err = bigchain.IndividualFulfillTx(tx, privkey); err != nil {
			return nil, err
		}
	}
	if signatures != nil {
		if err = bigchain.MultipleFulfillTx(tx, pubkeys, signatures); err != nil {
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
	recordLabels := spec.GetRecordLabels(recording)
	n += len(recordLabels)
	ownersBefore, err := CheckTxOwnersBefore(recordingTx, n)
	if err != nil {
		return err
	}
	outputs := bigchain.GetTxOutputs(recordingTx)
	if n != len(outputs) {
		return Error("different number of artists/record labels and outputs")
	}
	compositionId := spec.GetRecordingOfId(recording)
	if _, err := ValidateCompositionId(compositionId); err != nil {
		return err
	}
	licenseHolders := make(map[string][]string)
	parties := append(artists, recordLabels...)
	rightHolders := make(map[string][]string)
	totalShares := 0
OUTER:
	for i, party := range parties {
		partyId := spec.GetId(party)
		tx, err := ValidateUserId(partyId)
		if err != nil {
			return err
		}
		if !ownersBefore[i].Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("artist/record label isn't tx ownerBefore")
		}
		ownerAfter, err := CheckOutputOwnerAfter(outputs[i])
		if err != nil {
			return err
		}
		if !ownerAfter.Equals(ownersBefore[i]) {
			return Error("artist/record label isn't output ownerAfter")
		}
		if totalShares += bigchain.GetOutputAmount(outputs[i]); totalShares > 100 {
			return Error("total shares exceed 100")
		}
		licenseId := spec.GetLicenseId(party)
		if !EmptyStr(licenseId) {
			licenseHolderIds, ok := licenseHolders[licenseId]
			if !ok {
				tx, err = ValidateLicenseId(licenseId)
				if err != nil {
					return err
				}
				license := bigchain.GetTxAssetData(tx)
				for _, licenseForId := range spec.GetLicenseForIds(license) {
					if compositionId == licenseForId {
						licenseHolderIds = spec.GetLicenseHolderIds(license)
						goto NEXT
					}
				}
				return Error("license does not link to composition")
			}
		NEXT:
			for i, licenseHolderId := range licenseHolderIds {
				if licenseHolderId == partyId {
					licenseHolderIds = append(licenseHolderIds[:i], licenseHolderIds[i+1:]...)
					licenseHolders[licenseId] = licenseHolderIds
					continue OUTER
				}
			}
			return Error("artist/record label doesn't have mechanical")
		}
		rightId := spec.GetRightId(party)
		if !EmptyStr(rightId) {
			rightHolderIds, ok := rightHolders[rightId]
			if !ok {
				tx, _, err := CheckRightHolder(partyId, rightId)
				if err != nil {
					return err
				}
				right := bigchain.GetTxAssetData(tx)
				if compositionId != spec.GetRightToId(right) {
					return Error("right doesn't link to composition")
				}
				rightHolderIds = spec.GetRightHolderIds(right)
			}
			for i, rightHolderId := range rightHolderIds {
				if rightHolderId == partyId {
					rightHolderIds = append(rightHolderIds[:i], rightHolderIds[i+1:]...)
					rightHolders[rightId] = rightHolderIds
					continue OUTER
				}
			}
			return Error("artist/record label isn't right-holder")
		}
		txIds, _, err := bigchain.HttpGetOutputs(ownerAfter, true)
		if err != nil {
			return err
		}
		for _, txId := range txIds {
			if compositionId == txId {
				continue OUTER
			}
		}
		return Error("artist/record label isn't composer/publisher")
	}
	if totalShares != 100 {
		return Error("total shares do not equal 100")
	}
	return nil
}

func CheckArtist(artistId, recordingId string) (Data, crypto.PublicKey, error) {
	tx, err := ValidateRecordingId(recordingId)
	if err != nil {
		return nil, nil, err
	}
	artists := spec.GetArtists(bigchain.GetTxAssetData(tx))
	for i, artist := range artists {
		if artistId == spec.GetId(artist) {
			return tx, bigchain.DefaultTxOwnerAfter(tx, i), nil
		}
	}
	return nil, nil, Error("couldn't match artist id")
}

func ProveArtist(artistId, challenge string, privkey crypto.PrivateKey, recordingId string) (crypto.Signature, error) {
	_, pubkey, err := CheckArtist(artistId, recordingId)
	if err != nil {
		return nil, err
	}
	if !pubkey.Equals(privkey.Public()) {
		return nil, ErrInvalidKey
	}
	return privkey.Sign(Checksum256([]byte(challenge))), nil
}

func VerifyArtist(artistId, challenge string, recordingId string, sig crypto.Signature) error {
	_, pubkey, err := CheckArtist(artistId, recordingId)
	if err != nil {
		return err
	}
	if !pubkey.Verify(Checksum256([]byte(challenge)), sig) {
		return ErrInvalidSignature
	}
	return nil
}

func CheckRecordLabel(recordingId, recordLabelId string) (Data, crypto.PublicKey, error) {
	tx, err := ValidateRecordingId(recordingId)
	if err != nil {
		return nil, nil, err
	}
	recordLabels := spec.GetRecordLabels(bigchain.GetTxAssetData(tx))
	for i, recordLabel := range recordLabels {
		if recordLabelId == spec.GetId(recordLabel) {
			return tx, bigchain.DefaultTxOwnerAfter(tx, i), nil
		}
	}
	return nil, nil, Error("couldn't match record label id")
}

func ProveRecordLabel(challenge string, privkey crypto.PrivateKey, recordingId, recordLabelId string) (crypto.Signature, error) {
	_, pubkey, err := CheckRecordLabel(recordingId, recordLabelId)
	if err != nil {
		return nil, err
	}
	if !pubkey.Equals(privkey.Public()) {
		return nil, ErrInvalidKey
	}
	return privkey.Sign(Checksum256([]byte(recordLabelId))), nil
}

func VerifyRecordLabel(challenge string, recordingId, recordLabelId string, sig crypto.Signature) error {
	_, pubkey, err := CheckRecordLabel(recordingId, recordLabelId)
	if err != nil {
		return err
	}
	if !pubkey.Verify(Checksum256([]byte(challenge)), sig) {
		return ErrInvalidSignature
	}
	return nil
}
