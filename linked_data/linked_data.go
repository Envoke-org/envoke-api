package linked_data

import (
	"bytes"

	"github.com/zbo14/balloon"
	"github.com/zbo14/envoke/bigchain"
	. "github.com/zbo14/envoke/common"
	cc "github.com/zbo14/envoke/crypto/conditions"
	"github.com/zbo14/envoke/crypto/crypto"
	"github.com/zbo14/envoke/schema"
	"github.com/zbo14/envoke/spec"
)

func QueryAndValidateSchema(id string, _type string) (Data, error) {
	tx, err := bigchain.HttpGetTx(id)
	if err != nil {
		return nil, err
	}
	data := bigchain.GetTxAssetData(tx)
	if err = schema.ValidateSchema(data, _type); err != nil {
		return nil, err
	}
	return tx, nil
}

var SALT = balloon.GenerateSalt()

func DefaultBalloonHash(challenge string) ([]byte, error) {
	p, err := Base64UrlDecode(challenge)
	if err != nil {
		return nil, err
	}
	// TODO: adjust params
	return balloon.BalloonHash(p, SALT, 256, 32, 2), nil
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
	return schema.ValidateSchema(bigchain.GetTxAssetData(tx), "user")
}

func ValidateCompositionId(id string) (Data, error) {
	tx, err := QueryAndValidateSchema(id, "composition")
	if err != nil {
		return nil, err
	}
	if err = ValidateCompositionTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateCompositionTx(tx Data) (err error) {
	composition := bigchain.GetTxAssetData(tx)
	composers := spec.GetComposers(composition)
	outputs := bigchain.GetTxOutputs(tx)
	n := len(composers)
	if n != len(outputs) {
		return Error("number of outputs doesn't equal number of composers")
	}
	composerKeys := make([]crypto.PublicKey, n)
	totalShares := 0
OUTER:
	for i, composer := range composers {
		// TODO: check for repeat pubkeys
		tx, err = QueryAndValidateSchema(spec.GetId(composer), "user")
		if err != nil {
			return err
		}
		composerKeys[i] = bigchain.DefaultTxOwnerBefore(tx)
		if composerKeys[i].Equals(bigchain.DefaultOutputOwnerAfter(outputs[i])) {
			if totalShares += bigchain.GetOutputAmount(outputs[i]); totalShares > 100 {
				return Error("total shares exceed 100")
			}
			continue OUTER
		}
		return Error("could not find output with composer pubkey")
	}
	if totalShares != 100 {
		return Error("total shares do not equal 100")
	}
	if n > 1 {
		thresholdSignature := spec.GetThresholdSignature(composition)
		ful, err := cc.DefaultUnmarshalURI(thresholdSignature)
		if err != nil {
			return err
		}
		thresholdFulfillment := cc.DefaultFulfillmentThresholdFromPubKeys(composerKeys)
		if cc.GetCondition(ful).String() != cc.GetCondition(thresholdFulfillment).String() {
			return ErrInvalidCondition
		}
		composition.Delete("thresholdSignature")
		buf := new(bytes.Buffer)
		checksum := Checksum256(MustMarshalJSON(composition))
		for i := 0; i < n; i++ {
			WriteVarOctet(buf, checksum)
		}
		if !ful.Validate(buf.Bytes()) {
			return ErrorAppend(ErrInvalidFulfillment, ful.String())
		}
		composition.Set("thresholdSignature", thresholdSignature)
	}
	publisherId := spec.GetPublisherId(composition)
	if !EmptyStr(publisherId) {
		if _, err = QueryAndValidateSchema(publisherId, "user"); err != nil {
			return err
		}
	}
	return nil
}

func ProveComposer(challenge, composerId string, compositionId string, priv crypto.PrivateKey) (crypto.Signature, error) {
	tx, err := ValidateCompositionId(compositionId)
	if err != nil {
		return nil, err
	}
	composers := spec.GetComposers(bigchain.GetTxAssetData(tx))
	for _, composer := range composers {
		if composerId == spec.GetId(composer) {
			tx, err := bigchain.HttpGetTx(composerId)
			if err != nil {
				return nil, err
			}
			if pub := priv.Public(); !pub.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
				return nil, ErrorAppend(ErrInvalidKey, pub.String())
			}
			hash, err := DefaultBalloonHash(challenge)
			if err != nil {
				return nil, err
			}
			return priv.Sign(hash), nil
		}
	}
	return nil, ErrorAppend(ErrInvalidId, "could not match composerId")
}

func VerifyComposer(challenge, composerId, compositionId string, sig crypto.Signature) error {
	tx, err := ValidateCompositionId(compositionId)
	if err != nil {
		return err
	}
	composers := spec.GetComposers(bigchain.GetTxAssetData(tx))
	found := false
	for _, composer := range composers {
		if composerId == spec.GetId(composer) {
			found = true
			break
		}
	}
	if !found {
		return Error("composer not found")
	}
	if err != nil {
		return err
	}
	hash, err := DefaultBalloonHash(challenge)
	if err != nil {
		return err
	}
	pubkey := bigchain.DefaultTxOwnerBefore(tx)
	if !pubkey.Verify(hash, sig) {
		return ErrorAppend(ErrInvalidSignature, sig.String())
	}
	return nil
}

func ValidateRightId(id string) (Data, error) {
	tx, err := QueryAndValidateSchema(id, "right")
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
	rightHolderIds := spec.GetRightHolderIds(right)
	n := len(rightHolderIds)
	if n != 1 && n != 2 {
		return Error("must be 1 or 2 right-holder ids")
	}
	outputs := bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return Error("right must have same number of outputs as right-holder ids")
	}
	var recipientKey crypto.PublicKey
	senderKey := bigchain.DefaultTxOwnerBefore(tx)
	for i, rightHolderId := range rightHolderIds {
		tx, err = QueryAndValidateSchema(rightHolderId, "user")
		if err != nil {
			return err
		}
		rightHolderKey := bigchain.DefaultTxOwnerBefore(tx)
		if !rightHolderKey.Equals(bigchain.DefaultOutputOwnerAfter(outputs[i])) {
			return Error("right-holder does not hold output")
		}
		if senderKey.Equals(rightHolderKey) {
			if i == 1 || n == 1 {
				return Error("sender cannot be only/second right-holder")
			}
		} else {
			if i == 0 && n == 2 {
				return Error("sender is not first right-holder")
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
		err = ErrorAppend(ErrInvalidType, "Expected MusicComposition or MusicRecording; got "+rightToType)
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
		return Error("expected TRANSFER tx")
	}
	if !senderKey.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
		return Error("right sender is not sender of TRANSFER tx")
	}
	outputs = bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return Error("TRANSFER tx outputs must have same size as right-holder ids")
	}
	if n == 1 {
		if !recipientKey.Equals(bigchain.DefaultOutputOwnerAfter(outputs[0])) {
			return Error("recipient does not hold TRANSFER tx output")
		}
		recipientShares := bigchain.GetOutputAmount(outputs[0])
		if recipientShares <= 0 || recipientShares > 100 {
			return Error("recipient shares must be greater than 0 and less than/equal to 100")
		}
	}
	if n == 2 {
		if !recipientKey.Equals(bigchain.DefaultOutputOwnerAfter(outputs[1])) {
			return Error("recipient does not hold TRANSFER tx output")
		}
		recipientShares := bigchain.GetOutputAmount(outputs[1])
		if recipientShares <= 0 || recipientShares > 100 {
			return Error("recipient shares must be greater than 0 and less than/equal to 100")
		}
		if !senderKey.Equals(bigchain.DefaultOutputOwnerAfter(outputs[0])) {
			return Error("sender does not hold TRANSFER tx output")
		}
		senderShares := bigchain.GetOutputAmount(outputs[0])
		if senderShares <= 0 || senderShares >= 100 {
			return Error("sender shares must be greater than 0 and less than 100")
		}
	}
	if rightToId != bigchain.GetTxAssetId(tx) {
		return Error("TRANSFER tx does not link to " + rightToType)
	}
	return nil
}

func CheckRightIdHolder(rightHolderId, rightId string) (crypto.PublicKey, error) {
	tx, err := ValidateRightId(rightId)
	if err != nil {
		return nil, err
	}
	return CheckRightTxHolder(rightHolderId, tx)
}

func CheckRightTxHolder(rightHolderId string, tx Data) (crypto.PublicKey, error) {
	right := bigchain.GetTxAssetData(tx)
	rightHolderIds := spec.GetRightHolderIds(right)
	for i := range rightHolderIds {
		if rightHolderId == rightHolderIds[i] {
			rightHolderKey := bigchain.DefaultTxOwnerAfter(tx, i)
			transferId := spec.GetTransferId(right)
			txs, err := bigchain.HttpGetTransfers(spec.GetRightToId(right))
			if err != nil {
				return nil, err
			}
			for _, tx := range txs {
				consume := bigchain.DefaultTxConsume(tx)
				if transferId == consume.GetStr("txid") {
					if i == consume.GetInt("output") {
						return nil, Error("TRANSFER tx output has been spent")
					}
				}
			}
			return rightHolderKey, nil
		}
	}
	return nil, ErrorAppend(ErrInvalidId, "could not match rightHolderId")
}

func ProveRightHolder(challenge string, priv crypto.PrivateKey, rightHolderId, rightId string) (crypto.Signature, error) {
	rightHolderKey, err := CheckRightIdHolder(rightHolderId, rightId)
	if err != nil {
		return nil, err
	}
	if pub := priv.Public(); !rightHolderKey.Equals(pub) {
		return nil, ErrorAppend(ErrInvalidKey, pub.String())
	}
	hash, err := DefaultBalloonHash(challenge)
	if err != nil {
		return nil, err
	}
	return priv.Sign(hash), nil
}

func VerifyRightHolder(challenge string, rightHolderId, rightId string, sig crypto.Signature) error {
	rightHolderKey, err := CheckRightIdHolder(rightHolderId, rightId)
	if err != nil {
		return err
	}
	hash, err := DefaultBalloonHash(challenge)
	if err != nil {
		return err
	}
	if !rightHolderKey.Verify(hash, sig) {
		return ErrorAppend(ErrInvalidSignature, sig.String())
	}
	return nil
}

func ValidateLicenseId(id string) (Data, error) {
	tx, err := QueryAndValidateSchema(id, "license")
	if err != nil {
		return nil, err
	}
	if err = ValidateLicenseTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateLicenseTx(tx Data) (err error) {
	license := bigchain.GetTxAssetData(tx)
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	licenserId := spec.GetLicenserId(license)
	licenserKey := bigchain.DefaultTxOwnerBefore(tx)
	outputs := bigchain.GetTxOutputs(tx)
	for i, licenseHolderId := range licenseHolderIds {
		if licenserId == licenseHolderId {
			return Error("licenser cannot be license-holder")
		}
		tx, err = QueryAndValidateSchema(licenseHolderId, "user")
		if err != nil {
			return err
		}
		licenseHolderKey := bigchain.DefaultTxOwnerBefore(tx)
		if !licenseHolderKey.Equals(bigchain.DefaultOutputOwnerAfter(outputs[i])) {
			return ErrorAppend(ErrInvalidKey, licenseHolderKey.String())
		}
	}
	tx, err = QueryAndValidateSchema(licenserId, "user")
	if err != nil {
		return err
	}
	if !licenserKey.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
		return ErrorAppend(ErrInvalidKey, licenserKey.String())
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
			err = ErrorAppend(ErrInvalidType, "Expected MusicComposition or MusicRecording; got "+licensedType)
		}
		if err != nil {
			return err
		}
		rightId := spec.GetRightId(licenseFor[i])
		if !EmptyStr(rightId) {
			tx, err := ValidateRightId(rightId)
			if err != nil {
				return err
			}
			if _, err = CheckRightTxHolder(licenserId, tx); err != nil {
				return err
			}
			right := bigchain.GetTxAssetData(tx)
			if licenseForId != spec.GetRightToId(right) {
				return ErrorAppend(ErrInvalidId, "right has wrong compositionId/recordingId")
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
		return Error("licenser is not artist/composer or right-holder")
	}
	return nil
}

func ProveLicenseHolder(challenge, licenseHolderId, licenseId string, priv crypto.PrivateKey) (crypto.Signature, error) {
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
			if pubkey := priv.Public(); !licenseHolderKey.Equals(pubkey) {
				return nil, ErrorAppend(ErrInvalidKey, pubkey.String())
			}
			hash, err := DefaultBalloonHash(challenge)
			if err != nil {
				return nil, err
			}
			return priv.Sign(hash), nil
		}
	}
	return nil, ErrorAppend(ErrInvalidId, licenseHolderId)
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
			hash, err := DefaultBalloonHash(challenge)
			if err != nil {
				return err
			}
			if !licenseHolderKey.Verify(hash, sig) {
				return ErrorAppend(ErrInvalidSignature, sig.String())
			}
			return nil
		}
	}
	return ErrorAppend(ErrInvalidId, licenseHolderId)
}

func ValidateRecordingId(id string) (Data, error) {
	tx, err := QueryAndValidateSchema(id, "recording")
	if err != nil {
		return nil, err
	}
	if err = ValidateRecordingTx(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func ValidateRecordingTx(tx Data) (err error) {
	outputs := bigchain.GetTxOutputs(tx)
	recording := bigchain.GetTxAssetData(tx)
	artists := spec.GetArtists(recording)
	n := len(artists)
	if n != len(outputs) {
		return Error("number of outputs doesn't equal number of artists")
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
		tx, err = ValidateLicenseId(licenseId)
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
		return ErrorAppend(ErrInvalidId, "license does not have compositionId")
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
			return err
		}
		artistKeys[i] = bigchain.DefaultTxOwnerBefore(tx)
		if !artistKeys[i].Equals(bigchain.DefaultOutputOwnerAfter(outputs[i])) {
			return Error("artist does not hold output")
		}
		if totalShares += bigchain.GetOutputAmount(outputs[i]); totalShares > 100 {
			return Error("total shares exceed 100")
		}
		for j, composer := range composers {
			if artistId == spec.GetId(composer) {
				composers = append(composers[:j], composers[j+1:]...)
				continue OUTER
			}
		}
		if len(licenseHolderIds) > 0 {
			for j, licenseHolderId := range licenseHolderIds {
				if artistId == licenseHolderId {
					licenseHolderIds = append(licenseHolderIds[:j], licenseHolderIds[j+1:]...)
					continue OUTER
				}
			}
		}
		return Error("artist is not composer/does not have mechanical")
	}
	if totalShares != 100 {
		return Error("total shares do not equal 100")
	}
	if n > 1 {
		thresholdSignature := spec.GetThresholdSignature(recording)
		ful, err := cc.DefaultUnmarshalURI(thresholdSignature)
		if err != nil {
			return err
		}
		thresholdFulfillment := cc.DefaultFulfillmentThresholdFromPubKeys(artistKeys)
		if cc.GetCondition(ful).String() != cc.GetCondition(thresholdFulfillment).String() {
			return ErrInvalidCondition
		}
		recording.Delete("thresholdSignature")
		buf := new(bytes.Buffer)
		checksum := Checksum256(MustMarshalJSON(recording))
		for i := 0; i < n; i++ {
			WriteVarOctet(buf, checksum)
		}
		if !ful.Validate(buf.Bytes()) {
			return ErrorAppend(ErrInvalidFulfillment, ful.String())
		}
		recording.Set("thresholdSignature", thresholdSignature)
	}
	recordLabelId := spec.GetRecordLabelId(recording)
	if !EmptyStr(recordLabelId) {
		if _, err = ValidateUserId(recordLabelId); err != nil {
			return err
		}
		for i, licenseHolderId := range licenseHolderIds {
			if recordLabelId == licenseHolderId {
				licenseHolderIds = append(licenseHolderIds[:i], licenseHolderIds[i+1:]...)
				goto END
			}
		}
		return ErrorAppend(ErrInvalidId, "wrong licenseHolderId")
	}
END:
	return nil
}

func ProveArtist(artistId, challenge string, priv crypto.PrivateKey, recordingId string) (crypto.Signature, error) {
	tx, err := ValidateRecordingId(recordingId)
	if err != nil {
		return nil, err
	}
	artists := spec.GetArtists(bigchain.GetTxAssetData(tx))
	for _, artist := range artists {
		if artistId == spec.GetId(artist) {
			tx, err := bigchain.HttpGetTx(artistId)
			if err != nil {
				return nil, err
			}
			if pubkey := priv.Public(); !pubkey.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
				return nil, ErrorAppend(ErrInvalidKey, pubkey.String())
			}
			hash, err := DefaultBalloonHash(challenge)
			if err != nil {
				return nil, err
			}
			return priv.Sign(hash), nil
		}
	}
	return nil, ErrorAppend(ErrInvalidId, "could not match artistId")
}

func VerifyArtist(artistId, challenge string, recordingId string, sig crypto.Signature) error {
	tx, err := ValidateRecordingId(recordingId)
	if err != nil {
		return err
	}
	artists := spec.GetArtists(bigchain.GetTxAssetData(tx))
	for _, artist := range artists {
		if artistId == spec.GetId(artist) {
			tx, err := bigchain.HttpGetTx(artistId)
			if err != nil {
				return err
			}
			artistKey := bigchain.DefaultTxOwnerBefore(tx)
			hash, err := DefaultBalloonHash(challenge)
			if err != nil {
				return err
			}
			if !artistKey.Verify(hash, sig) {
				return ErrorAppend(ErrInvalidSignature, sig.String())
			}
			return nil
		}
	}
	return ErrorAppend(ErrInvalidId, "could not match artistId")
}

/*
func ValidateReleaseId(releaseId string) (Data, error) {
	tx, err := QueryAndValidateSchema(releaseId, "release")
	if err != nil {
		return nil, err
	}
	release := bigchain.GetTxAssetData(tx)
	recordLabelId := spec.GetRecordLabelId(release)
	recordLabelKey := bigchain.DefaultTxOwnerBefore(tx)
	tx, err = QueryAndValidateSchema(recordLabelId, "user")
	if err != nil {
		return nil, err
	}
	if !recordLabelKey.Equals(bigchain.DefaultTxOwnerBefore(tx)) {
		return nil, ErrorAppend(ErrInvalidKey, recordLabelKey.String())
	}
	recordings := spec.GetRecordings(release)
OUTER:
	for _, recording := range recordings {
		recordingId := spec.GetId(recording)
		recording, err := ValidateRecordingId(recordingId)
		if err != nil {
			return nil, err
		}
		if recordLabelId != spec.GetRecordLabelId(recording) {
			return nil, ErrorAppend(ErrInvalidId, recordLabelId)
		}
		rightId := spec.GetRightId(recording)
		right, err := ValidateRightId(recordLabelId, rightId)
		if err != nil {
			return nil, err
		}
		if recordingId != spec.GetRightToId(right) {
			return nil, ErrorAppend(ErrInvalidId, "recording right has wrong recordingId")
		}
		rightHolderIds := spec.GetRightHolderIds(right)
		for _, rightHolderId := range rightHolderIds {
			if recordLabelId == rightHolderId {
				continue OUTER
			}
		}
		return nil, Error("record label is not recording right-holder")
	}
	return release, nil
}

func ProveRecordLabel(challenge string, priv crypto.PrivateKey, releaseId string) (crypto.Signature, error) {
	release, err := ValidateReleaseId(releaseId)
	if err != nil {
		return nil, err
	}
	recordLabelId := spec.GetRecordLabelId(release)
	tx, err := bigchain.HttpGetTx(recordLabelId)
	if err != nil {
		return nil, err
	}
	pubkey := bigchain.DefaultTxOwnerBefore(tx)
	if pub := priv.Public(); !pubkey.Equals(pub) {
		return nil, ErrorAppend(ErrInvalidKey, pub.String())
	}
	hash, err := DefaultBalloonHash(challenge)
	if err != nil {
		return nil, err
	}
	return priv.Sign(hash), nil
}

func VerifyRecordLabel(challenge, releaseId string, sig crypto.Signature) error {
	release, err := ValidateReleaseId(releaseId)
	if err != nil {
		return err
	}
	recordLabelId := spec.GetRecordLabelId(release)
	tx, err := bigchain.HttpGetTx(recordLabelId)
	if err != nil {
		return err
	}
	hash, err := DefaultBalloonHash(challenge)
	if err != nil {
		return err
	}
	pubkey := bigchain.DefaultTxOwnerBefore(tx)
	if !pubkey.Verify(hash, sig) {
		return ErrorAppend(ErrInvalidSignature, sig.String())
	}
	return nil
}
*/
