package linked_data

import (
	"github.com/Envoke-org/envoke-api/bigchain"
	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	// "github.com/Envoke-org/envoke-api/crypto/ed25519"
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

func BuildCompositionTx(composition Data, signatures []string, splits []int) (Data, error) {
	composers := spec.GetComposers(composition)
	n := len(composers)
	if n == 0 {
		return nil, Error("no composers")
	}
	publishers := spec.GetPublishers(composition)
	n += len(publishers)
	if signatures != nil {
		if n != len(signatures) {
			return nil, Error("different number of parties and signatures")
		}
	}
	if n != len(splits) {
		return nil, Error("different number of parties and splits")
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
	if consumeId != rightToId {
		if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
			return nil, nil, Error("expected TRANSFER tx")
		}
		if _, err := CheckTxOwnerBefore(tx); err != nil {
			return nil, nil, err
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
				tx, err := bigchain.TransferTx([]int{transferAmount}, rightToId, consumeId, idx, []crypto.PublicKey{recipientKey}, []crypto.PublicKey{senderKey})
				if err != nil {
					return nil, nil, err
				}
				return tx, []string{recipientId}, nil
			}
			if keepAmount > 0 {
				tx, err := bigchain.TransferTx([]int{keepAmount, transferAmount}, rightToId, consumeId, idx, []crypto.PublicKey{senderKey, recipientKey}, []crypto.PublicKey{senderKey})
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
		return bigchain.CreateTx([]int{1}, right, []crypto.PublicKey{recipientKey}, []crypto.PublicKey{senderKey})
	}
	return bigchain.CreateTx([]int{1, 1}, right, []crypto.PublicKey{senderKey, recipientKey}, []crypto.PublicKey{senderKey})
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
	transferId := spec.GetTransferId(right)
	tx, err = bigchain.HttpGetTx(transferId)
	if err != nil {
		return err
	}
	if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
		return Error("expected TRANSFER")
	}
	transferOwnerBefore, err := CheckTxOwnerBefore(tx)
	if err != nil {
		return err
	}
	if !ownerBefore.Equals(transferOwnerBefore) {
		return Error("right ownerBefore isn't TRANSFER ownerBefore")
	}
	outputs = bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return Error("different number of TRANSFER tx outputs and right-holder ids")
	}
	idx := 0
	if n == 2 {
		ownerAfter, err := CheckOutputOwnerAfter(outputs[0])
		if err != nil {
			return err
		}
		if !ownerAfter.Equals(ownerBefore) {
			return Error("ownerBefore isn't TRANSFER ownerAfter")
		}
		senderShares := bigchain.GetOutputAmount(outputs[0])
		if senderShares <= 0 || senderShares >= 100 {
			return Error("sender shares must be greater than 0 and less than 100")
		}
		idx = 1
	}
	ownerAfter, err := CheckOutputOwnerAfter(outputs[idx])
	if err != nil {
		return err
	}
	if !ownerAfter.Equals(recipientKey) {
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

/*

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

func BuildLicenseTx(license Data, licenserKey crypto.PublicKey) (Data, error) {
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	n := len(licenseHolderIds)
	amounts := make([]int, n)
	licenserId := spec.GetLicenserId(license)
	pubkeys := make([]crypto.PublicKey, n)
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
		return nil, Error("licenser isn't right-holder")
	}
	if n == 1 {
		return bigchain.IndividualCreateTx(amounts[0], license, pubkeys[0], licenserKey)
	}
	return bigchain.MultipleOwnersCreateTx(amounts, license, pubkeys, licenserKey)
}

func ValidateLicenseTx(tx Data) (err error) {
	license := bigchain.GetTxAssetData(tx)
	if err := schema.ValidateSchema(license, "license"); err != nil {
		return err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	n := len(licenseHolderIds)
	licenserId := spec.GetLicenserId(license)
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

func BuildRecordingTx(recording Data, signatures []string, splits []int) (Data, error) {
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
	parties := append(artists, recordLabels...)
	pubkeys := make([]crypto.PublicKey, n)
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
		for j, composer := range composers {
			if partyId == spec.GetId(composer) {
				composers = append(composers[:j], composers[j+1:]...)
				continue OUTER
			}
		}
		for j, publisher := range publishers {
			if partyId == spec.GetId(publisher) {
				publishers = append(publishers[:j], publishers[j+1:]...)
				continue OUTER
			}
		}
		for j, licenseHolderId := range licenseHolderIds {
			if partyId == licenseHolderId {
				licenseHolderIds = append(licenseHolderIds[:j], licenseHolderIds[j+1:]...)
				continue OUTER
			}
		}
		return nil, Error("artist/record label isn't composer/publisher/doesn't have mechanical")
	}
		if totalShares != 100 {
			return nil, Error("total shares do not equal 100")
		}
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
	ownerBefore, err := CheckTxOwnerBefore(recordingTx)
	if err != nil {
		return err
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
		ownerAfter, err := CheckOutputOwnerAfter(outputs[i])
		if err != nil {
			return err
		}
		if !ownerAfter.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
			return Error("artist isn't ownerAfter")
		}
		if totalShares += bigchain.GetOutputAmount(outputs[i]); totalShares > 100 {
			return Error("total shares exceed 100")
		}
		artistKeys[i] = ownerAfter
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
		if !ownerBefore.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
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
		if !ownerBefore.Equals(artistKeys[0]) {
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
*/
