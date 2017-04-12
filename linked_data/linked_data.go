package linked_data

import (
	"github.com/Envoke-org/envoke-api/bigchain"
	. "github.com/Envoke-org/envoke-api/common"
	cc "github.com/Envoke-org/envoke-api/crypto/conditions"
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
	if len(composers) == 0 {
		return nil, Error("no composers")
	}
	publishers := spec.GetPublishers(composition)
	if signatures != nil {
		if len(signatures) != len(composers)+len(publishers) {
			return nil, Error("different number of composers/publishers and signatures")
		}
	}
	if len(splits) != len(composers)+len(publishers) {
		return nil, Error("different number of composers/publishers and splits")
	}
	parties := append(composers, publishers...)
	pubkeys := make([]crypto.PublicKey, len(composers)+len(publishers))
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
		return nil, Error("total shares don't equal 100")
	}
	tx, err := bigchain.CreateTx(splits, composition, pubkeys, pubkeys)
	if err != nil {
		return nil, err
	}
	if len(composers)+len(publishers) == 1 {
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
	if len(composers) == 0 {
		return Error("no composers")
	}
	publishers := spec.GetPublishers(composition)
	ownersBefore, err := CheckTxOwnersBefore(compositionTx, len(composers)+len(publishers))
	if err != nil {
		return err
	}
	outputs := bigchain.GetTxOutputs(compositionTx)
	if len(outputs) != len(composers)+len(publishers) {
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
		return Error("total shares don't equal 100")
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

func AssembleRightTx(assetId string, previousRightId string, privkey crypto.PrivateKey, pubkey crypto.PublicKey, recipientIds []string, splits []int) (Data, error) {
	if len(recipientIds) == 0 {
		return nil, Error("no recipients")
	}
	if len(recipientIds) != len(splits) {
		return nil, Error("different number of recipients and splits")
	}
	pubkeys := make([]crypto.PublicKey, len(recipientIds))
	for i, recipientId := range recipientIds {
		tx, err := ValidateUserId(recipientId)
		if err != nil {
			return nil, err
		}
		pubkeys[i] = bigchain.DefaultTxOwnerBefore(tx)
	}
	tx, err := bigchain.HttpGetTx(assetId)
	if err != nil {
		return nil, err
	}
	_type := spec.GetType(bigchain.GetTxAssetData(tx))
	if _type == "MusicComposition" {
		err = ValidateCompositionTx(tx)
	} else if _type == "MusicRecording" {
		err = ValidateRecordingTx(tx)
	} else {
		err = Error("expected MusicComposition or MusicRecording; got " + _type)
	}
	if err != nil {
		return nil, err
	}
	consumeId := assetId
	if spec.MatchId(previousRightId) {
		tx, err = CheckRightHolderKey(pubkey, previousRightId)
		if err != nil {
			return nil, err
		}
		if assetId != bigchain.GetTxAssetId(tx) {
			return nil, Error("previous right doesn't link to composition/recording")
		}
		consumeId = previousRightId
	}
	txIds, outputs, err := bigchain.HttpGetOutputs(pubkey, true)
	if err != nil {
		return nil, err
	}
	var i int
	for i = range txIds {
		if consumeId == txIds[i] {
			split := bigchain.GetOutputAmount(bigchain.GetTxOutput(tx, outputs[i]))
			for i := range splits {
				split -= splits[i]
			}
			if split == 0 {
				tx, err = bigchain.TransferTx(splits, assetId, consumeId, outputs[i], pubkeys, []crypto.PublicKey{pubkey})
			} else if split > 0 {
				pubkeys = append([]crypto.PublicKey{pubkey}, pubkeys...)
				splits = append([]int{split}, splits...)
				tx, err = bigchain.TransferTx(splits, assetId, consumeId, outputs[i], pubkeys, []crypto.PublicKey{pubkey})
			} else {
				err = Error("you cannot transfer that many shares")
			}
			if err != nil {
				return nil, err
			}
			if err = bigchain.IndividualFulfillTx(tx, privkey); err != nil {
				return nil, err
			}
			return tx, nil
		}
	}
	return nil, Error("you don't have unspent output in consume tx")
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

func ValidateRightTx(rightTx Data) (err error) {
	if bigchain.TRANSFER != bigchain.GetTxOperation(rightTx) {
		return Error("expected TRANSFER")
	}
	if _, err := CheckTxOwnerBefore(rightTx); err != nil {
		return err
	}
	assetId := bigchain.GetTxAssetId(rightTx)
	tx, err := bigchain.HttpGetTx(assetId)
	if err != nil {
		return err
	}
	_type := spec.GetType(bigchain.GetTxAssetData(tx))
	if _type == "MusicComposition" {
		err = ValidateCompositionTx(tx)
	} else if _type == "MusicRecording" {
		err = ValidateRecordingTx(tx)
	} else {
		err = Error("expected MusicComposition or MusicRecording; got " + _type)
	}
	if err != nil {
		return err
	}
	for _, output := range bigchain.GetTxOutputs(rightTx) {
		if _, err := CheckOutputOwnerAfter(output); err != nil {
			return err
		}
		percentShares := bigchain.GetOutputAmount(output)
		if percentShares <= 0 {
			return Error("shares should be greater than 0")
		}
		if percentShares > 100 {
			return Error("percent shares cannot be greater than 100")
		}
	}
	return nil
}

func CheckLicenseHolderId(licenseHolderId, licenseId string) (Data, crypto.PublicKey, error) {
	tx, err := ValidateUserId(licenseHolderId)
	if err != nil {
		return nil, nil, err
	}
	pubkey := bigchain.DefaultTxOwnerBefore(tx)
	tx, err = CheckLicenseHolderKey(licenseId, pubkey)
	if err != nil {
		return nil, nil, err
	}
	return tx, pubkey, nil
}

func CheckLicenseHolderKey(licenseId string, pubkey crypto.PublicKey) (Data, error) {
	tx, err := ValidateLicenseId(licenseId)
	if err != nil {
		return nil, err
	}
	for _, output := range bigchain.GetTxOutputs(tx) {
		if pubkey.Equals(bigchain.DefaultOutputOwnerAfter(output)) {
			return tx, nil
		}
	}
	return nil, Error("license-holder isn't ownerAfter")
}

func CheckRightHolderId(rightHolderId, rightId string) (Data, crypto.PublicKey, error) {
	tx, err := ValidateUserId(rightHolderId)
	if err != nil {
		return nil, nil, err
	}
	pubkey := bigchain.DefaultTxOwnerBefore(tx)
	tx, err = CheckRightHolderKey(pubkey, rightId)
	if err != nil {
		return nil, nil, err
	}
	return tx, pubkey, nil
}

func CheckRightHolderKey(pubkey crypto.PublicKey, rightId string) (Data, error) {
	tx, err := ValidateRightId(rightId)
	if err != nil {
		return nil, err
	}
	for _, output := range bigchain.GetTxOutputs(tx) {
		if pubkey.Equals(bigchain.DefaultOutputOwnerAfter(output)) {
			return tx, nil
		}
	}
	return nil, Error("couldn't match right-holder id")
}

func ProveRightHolder(challenge string, privkey crypto.PrivateKey, rightHolderId, rightId string) (crypto.Signature, error) {
	_, pubkey, err := CheckRightHolderId(rightHolderId, rightId)
	if err != nil {
		return nil, err
	}
	if !pubkey.Equals(privkey.Public()) {
		return nil, ErrInvalidKey
	}
	return privkey.Sign(Checksum256([]byte(challenge))), nil
}

func VerifyRightHolder(challenge string, rightHolderId, rightId string, sig crypto.Signature) error {
	_, rightHolderKey, err := CheckRightHolderId(rightHolderId, rightId)
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

func AssembleLicenseTx(assetIds []string, licenseHolderIds []string, privkey crypto.PrivateKey, pubkey crypto.PublicKey, validThrough string) (Data, error) {
	if len(licenseHolderIds) == 0 {
		return nil, Error("no license-holder ids")
	}
	amounts := make([]int, len(licenseHolderIds))
	pubkeys := make([]crypto.PublicKey, len(licenseHolderIds))
	for i, licenseHolderId := range licenseHolderIds {
		// TODO: check amount
		tx, err := ValidateUserId(licenseHolderId)
		if err != nil {
			return nil, err
		}
		pubkeys[i] = bigchain.DefaultTxOwnerBefore(tx)
		if pubkey.Equals(pubkeys[i]) {
			return nil, Error("licenser cannot be license-holder")
		}
		amounts[i] = 1
	}
OUTER:
	for _, assetId := range assetIds {
		tx, err := bigchain.HttpGetTx(assetId)
		if err != nil {
			return nil, err
		}
		asset := bigchain.GetTxAssetData(tx)
		_type := spec.GetType(asset)
		if _type == "MusicComposition" {
			err = ValidateCompositionTx(tx)
		} else if _type == "MusicRecording" {
			err = ValidateRecordingTx(tx)
		} else {
			err = Error("expected MusicComposition or MusicRecording; got " + _type)
		}
		if err != nil {
			return nil, err
		}
		txIds, _, err := bigchain.HttpGetOutputs(pubkey, true)
		if err != nil {
			return nil, err
		}
		txs, err := bigchain.HttpGetTransfers(assetId)
		if err != nil {
			return nil, err
		}
		for _, txId := range txIds {
			if txId == assetId {
				continue OUTER
			}
			for _, tx = range txs {
				if txId == spec.GetId(tx) {
					continue OUTER
				}
			}
		}
		return nil, Error("couldn't find licenser right")
	}
	license, err := spec.NewLicense(assetIds, validThrough)
	if err != nil {
		return nil, err
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

func ValidateLicenseTx(licenseTx Data) (err error) {
	license := bigchain.GetTxAssetData(licenseTx)
	if err := schema.ValidateSchema(license, "license"); err != nil {
		return err
	}
	ownerBefore, err := CheckTxOwnerBefore(licenseTx)
	if err != nil {
		return err
	}
	for _, output := range bigchain.GetTxOutputs(licenseTx) {
		// TODO: check amount
		if _, err = CheckOutputOwnerAfter(output); err != nil {
			return err
		}
	}
	assetIds := spec.GetAssetIds(license)
OUTER:
	for _, assetId := range assetIds {
		tx, err := bigchain.HttpGetTx(assetId)
		if err != nil {
			return err
		}
		asset := bigchain.GetTxAssetData(tx)
		_type := spec.GetType(asset)
		if _type == "MusicComposition" {
			err = ValidateCompositionTx(tx)
		} else if _type == "MusicRecording" {
			err = ValidateRecordingTx(tx)
		} else {
			err = Error("expected MusicComposition or MusicRecording; got " + _type)
		}
		if err != nil {
			return err
		}
		txIds, _, err := bigchain.HttpGetOutputs(ownerBefore, true)
		if err != nil {
			return err
		}
		txs, err := bigchain.HttpGetTransfers(assetId)
		if err != nil {
			return err
		}
		for _, txId := range txIds {
			if txId == assetId {
				continue OUTER
			}
			for _, tx = range txs {
				if txId == bigchain.GetTxId(tx) {
					continue OUTER
				}
			}
		}
		return Error("couldn't find licenser right")
	}
	fulfillment, err := cc.DefaultUnmarshalURI(spec.GetTimeout(license))
	if err != nil {
		return err
	}
	if !fulfillment.Validate(Int64Bytes(Now().Unix())) {
		return Error("license expired")
	}
	return nil
}

func ProveLicenseHolder(challenge, licenseHolderId, licenseId string, privkey crypto.PrivateKey) (crypto.Signature, error) {
	_, pubkey, err := CheckLicenseHolderId(licenseHolderId, licenseId)
	if err != nil {
		return nil, err
	}
	if !pubkey.Equals(privkey.Public()) {
		return nil, ErrInvalidKey
	}
	return privkey.Sign(Checksum256([]byte(challenge))), nil
}

func VerifyLicenseHolder(challenge, licenseHolderId, licenseId string, sig crypto.Signature) error {
	_, pubkey, err := CheckLicenseHolderId(licenseHolderId, licenseId)
	if err != nil {
		return err
	}
	if !pubkey.Verify(Checksum256([]byte(challenge)), sig) {
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
	if len(artists) == 0 {
		return nil, Error("no artists")
	}
	recordLabels := spec.GetRecordLabels(recording)
	if signatures != nil {
		if len(signatures) != len(artists)+len(recordLabels) {
			return nil, Error("different number of artists/record labels and signatures")
		}
	}
	if len(splits) != len(artists)+len(recordLabels) {
		return nil, Error("different number of artists/record labels and splits")
	}
	compositionId := spec.GetRecordingOfId(recording)
	if _, err := ValidateCompositionId(compositionId); err != nil {
		return nil, err
	}
	licenseHolders := make(map[string][]crypto.PublicKey)
	parties := append(artists, recordLabels...)
	pubkeys := make([]crypto.PublicKey, len(artists)+len(recordLabels))
	totalShares := 0
	txs, err := bigchain.HttpGetTransfers(compositionId)
	if err != nil {
		return nil, err
	}
OUTER:
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
		licenseId := spec.GetLicenseId(party)
		if !EmptyStr(licenseId) {
			if _, ok := licenseHolders[licenseId]; !ok {
				tx, err = ValidateLicenseId(licenseId)
				if err != nil {
					return nil, err
				}
				license := bigchain.GetTxAssetData(tx)
				for _, assetId := range spec.GetAssetIds(license) {
					if assetId == compositionId {
						for _, output := range bigchain.GetTxOutputs(tx) {
							licenseHolders[licenseId] = append(licenseHolders[licenseId], bigchain.DefaultOutputOwnerAfter(output))
						}
						goto NEXT
					}
				}
				return nil, Error("license doesn't link to composition")
			}
		NEXT:
			for j, licenseHolder := range licenseHolders[licenseId] {
				if licenseHolder.Equals(pubkeys[i]) {
					licenseHolders[licenseId] = append(licenseHolders[licenseId][:j], licenseHolders[licenseId][j+1:]...)
					continue OUTER
				}
			}
			return nil, Error("artist/record label doesn't have mechanical")
		}
		txIds, _, err := bigchain.HttpGetOutputs(pubkeys[i], true)
		if err != nil {
			return nil, err
		}
		for _, txId := range txIds {
			if txId == compositionId {
				continue OUTER
			}
			for _, tx = range txs {
				if txId == bigchain.GetTxId(tx) {
					continue OUTER
				}
			}
		}
		return nil, Error("artist/record label isn't composition right-holder")
	}
	if totalShares != 100 {
		return nil, Error("total shares don't equal 100")
	}
	tx, err := bigchain.CreateTx(splits, recording, pubkeys, pubkeys)
	if err != nil {
		return nil, err
	}
	if len(artists)+len(recordLabels) == 1 {
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
	if len(artists) == 0 {
		return Error("no artists")
	}
	recordLabels := spec.GetRecordLabels(recording)
	ownersBefore, err := CheckTxOwnersBefore(recordingTx, len(artists)+len(recordLabels))
	if err != nil {
		return err
	}
	outputs := bigchain.GetTxOutputs(recordingTx)
	if len(outputs) != len(artists)+len(recordLabels) {
		return Error("different number of artists/record labels and outputs")
	}
	compositionId := spec.GetRecordingOfId(recording)
	if _, err := ValidateCompositionId(compositionId); err != nil {
		return err
	}
	licenseHolders := make(map[string][]crypto.PublicKey)
	parties := append(artists, recordLabels...)
	totalShares := 0
	txs, err := bigchain.HttpGetTransfers(compositionId)
	if err != nil {
		return err
	}
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
			if _, ok := licenseHolders[licenseId]; !ok {
				tx, err = ValidateLicenseId(licenseId)
				if err != nil {
					return err
				}
				license := bigchain.GetTxAssetData(tx)
				for _, assetId := range spec.GetAssetIds(license) {
					if assetId == compositionId {
						for _, output := range bigchain.GetTxOutputs(tx) {
							licenseHolders[licenseId] = append(licenseHolders[licenseId], bigchain.DefaultOutputOwnerAfter(output))
						}
						goto NEXT
					}
				}
				return Error("license doesn't link to composition")
			}
		NEXT:
			for j, licenseHolder := range licenseHolders[licenseId] {
				if licenseHolder.Equals(ownerAfter) {
					licenseHolders[licenseId] = append(licenseHolders[licenseId][:j], licenseHolders[licenseId][j+1:]...)
					continue OUTER
				}
			}
			return Error("artist/record label doesn't have mechanical")
		}
		txIds, _, err := bigchain.HttpGetOutputs(ownerAfter, true)
		if err != nil {
			return err
		}
		for _, txId := range txIds {
			if txId == compositionId {
				continue OUTER
			}
			for _, tx = range txs {
				if txId == bigchain.GetTxId(tx) {
					continue OUTER
				}
			}
		}
		return Error("artist/record label isn't composition right-holder")
	}
	if totalShares != 100 {
		return Error("total shares don't equal 100")
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
