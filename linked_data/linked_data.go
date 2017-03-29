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
	model := bigchain.GetTxData(tx)
	if err = schema.ValidateSchema(model, _type); err != nil {
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

func ValidateCompositionId(compositionId string) (Data, error) {
	tx, err := bigchain.HttpGetTx(compositionId)
	if err != nil {
		return nil, err
	}
	composition := bigchain.GetTxData(tx)
	outputs := bigchain.GetTxOutputs(tx)
	return ValidateComposition(composition, outputs)
}

func ValidateComposition(composition Data, outputs []Data) (Data, error) {
	composers := spec.GetComposers(composition)
	n := len(composers)
	if n != len(outputs) {
		return nil, Error("number of outputs doesn't equal number of composers")
	}
	composerKeys := make([]crypto.PublicKey, n)
	totalShares := 0
OUTER:
	for i, composer := range composers {
		// TODO: check for repeat pubkeys
		tx, err := QueryAndValidateSchema(spec.GetId(composer), "user")
		if err != nil {
			return nil, err
		}
		composerKeys[i] = bigchain.DefaultGetTxSender(tx)
		for j, output := range outputs {
			if composerKeys[i].Equals(bigchain.GetOutputPublicKey(output)) {
				outputs = append(outputs[:j], outputs[i+j:]...)
				if totalShares += bigchain.GetOutputAmount(output); totalShares > 100 {
					return nil, Error("total shares exceed 100")
				}
				continue OUTER
			}
		}
		return nil, Error("could not find output with composer pubkey")
	}
	if totalShares != 100 {
		return nil, Error("total shares do not equal 100")
	}
	if n > 1 {
		thresholdSignature := spec.GetURI(composition)
		ful, err := cc.DefaultUnmarshalURI(thresholdSignature)
		if err != nil {
			return nil, err
		}
		thresholdFulfillment := cc.DefaultFulfillmentThresholdFromPubKeys(composerKeys)
		if cc.GetCondition(ful).String() != cc.GetCondition(thresholdFulfillment).String() {
			return nil, ErrInvalidCondition
		}
		composition.Delete("thresholdSignature")
		buf := new(bytes.Buffer)
		checksum := Checksum256(MustMarshalJSON(composition))
		for i := 0; i < n; i++ {
			WriteVarOctet(buf, checksum)
		}
		if !ful.Validate(buf.Bytes()) {
			return nil, ErrorAppend(ErrInvalidFulfillment, ful.String())
		}
		composition.Set("thresholdSignature", thresholdSignature)
	}
	publisherId := spec.GetPublisherId(composition)
	if !EmptyStr(publisherId) {
		if _, err := QueryAndValidateSchema(publisherId, "user"); err != nil {
			return nil, err
		}
	}
	return composition, nil
}

func ProveComposer(challenge, composerId, compositionId string, priv crypto.PrivateKey) (crypto.Signature, error) {
	composition, err := ValidateCompositionId(compositionId)
	if err != nil {
		return nil, err
	}
	composers := spec.GetComposers(composition)
	for _, composer := range composers {
		if composerId == spec.GetId(composer) {
			tx, err := bigchain.HttpGetTx(composerId)
			if err != nil {
				return nil, err
			}
			if pub := priv.Public(); !pub.Equals(bigchain.DefaultGetTxSender(tx)) {
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
	composition, err := ValidateCompositionId(compositionId)
	if err != nil {
		return err
	}
	composers := spec.GetComposers(composition)
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
	tx, err := bigchain.HttpGetTx(composerId)
	if err != nil {
		return err
	}
	hash, err := DefaultBalloonHash(challenge)
	if err != nil {
		return err
	}
	pubkey := bigchain.DefaultGetTxSender(tx)
	if !pubkey.Verify(hash, sig) {
		return ErrorAppend(ErrInvalidSignature, sig.String())
	}
	return nil
}

func ValidateRightId(rightHolderId, rightId string) (Data, error) {
	tx, err := QueryAndValidateSchema(rightId, "right")
	if err != nil {
		return nil, err
	}
	right := bigchain.GetTxData(tx)
	rightHolderIds := spec.GetRightHolderIds(right)
	n := len(rightHolderIds)
	if n != 1 && n != 2 {
		return nil, ErrorAppend(ErrInvalidSize, "right-holder ids must have size 1 or 2")
	}
	outputIdx := 0
	outputs := bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return nil, ErrorAppend(ErrInvalidSize, "right must have outputs with same size as right-holder ids")
	}
	var recipientKey crypto.PublicKey = nil
	senderKey := bigchain.DefaultGetTxSender(tx)
	for i := range rightHolderIds {
		tx, err = QueryAndValidateSchema(rightHolderIds[i], "user")
		if err != nil {
			return nil, err
		}
		rightHolderKey := bigchain.DefaultGetTxSender(tx)
		for j, output := range outputs {
			if rightHolderKey.Equals(bigchain.GetOutputPublicKey(output)) {
				outputs = append(outputs[:j], outputs[j+1:]...)
				goto NEXT
			}
		}
		return nil, Error("right-holder does not have right output")
	NEXT:
		if senderKey.Equals(rightHolderKey) {
			if n == 1 {
				return nil, Error("only right-holder is sender")
			}
		} else {
			if recipientKey != nil {
				return nil, Error("sender is not second right-holder")
			}
			if rightHolderId == rightHolderIds[i] {
				outputIdx = 1
			}
			recipientKey = rightHolderKey
		}
	}
	rightToId := spec.GetRightToId(right)
	tx, err = bigchain.HttpGetTx(rightToId)
	if err != nil {
		return nil, err
	}
	outputs = bigchain.GetTxOutputs(tx)
	rightTo := bigchain.GetTxData(tx)
	rightToType := spec.GetType(rightTo)
	if rightToType == "MusicComposition" {
		_, err = ValidateComposition(rightTo, outputs)
	} else if rightToType == "MusicRecording" {
		_, err = ValidateRecording(outputs, rightTo)
	} else {
		return nil, ErrorAppend(ErrInvalidType, "Expected MusicComposition or MusicRecording; got "+rightToType)
	}
	if err != nil {
		return nil, err
	}
	transferId := spec.GetTransferId(right)
	tx, err = bigchain.HttpGetTx(transferId)
	if err != nil {
		return nil, err
	}
	if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
		return nil, Error("expected TRANSFER tx")
	}
	if !senderKey.Equals(bigchain.DefaultGetTxSender(tx)) {
		return nil, Error("right sender is not sender of TRANSFER tx")
	}
	if n != len(bigchain.GetTxOutputs(tx)) {
		return nil, ErrorAppend(ErrInvalidSize, "TRANSFER tx outputs must have same size as right-holder ids")
	}
	if n == 1 {
		if !recipientKey.Equals(bigchain.GetTxRecipient(tx, 0)) {
			return nil, Error("recipient does not hold TRANSFER tx output")
		}
		recipientShares := bigchain.GetTxOutputAmount(tx, 0)
		if recipientShares <= 0 || recipientShares > 100 {
			return nil, Error("recipient shares must be greater than 0 and less than/equal to 100")
		}
		right.Set("recipientShares", recipientShares)
	}
	if n == 2 {
		if !recipientKey.Equals(bigchain.GetTxRecipient(tx, 1)) {
			return nil, Error("recipient does not hold TRANSFER tx output")
		}
		recipientShares := bigchain.GetTxOutputAmount(tx, 1)
		if recipientShares <= 0 || recipientShares > 100 {
			return nil, Error("recipient shares must be greater than 0 and less than/equal to 100")
		}
		right.Set("recipientShares", recipientShares)
		if !senderKey.Equals(bigchain.GetTxRecipient(tx, 0)) {
			return nil, Error("sender does not hold TRANSFER tx output")
		}
		senderShares := bigchain.GetTxOutputAmount(tx, 0)
		if senderShares <= 0 || senderShares >= 100 {
			return nil, Error("sender shares must be greater than 0 and less than 100")
		}
		right.Set("senderShares", senderShares)
	}
	if rightToId != bigchain.GetTxAssetId(tx) {
		return nil, Error("TRANSFER tx does not link to " + rightToType)
	}
	txs, err := bigchain.HttpGetTransfers(rightToId)
	if err != nil {
		return nil, err
	}
	for _, tx = range txs {
		if transferId == bigchain.GetTxConsumeId(tx, 0) {
			if outputIdx == bigchain.GetTxConsumeOutput(tx, 0) {
				return nil, Error("TRANSFER tx output has been spent")
			}
		}
	}
	return right, nil
}

func ProveRightHolder(challenge string, priv crypto.PrivateKey, rightHolderId, rightId string) (crypto.Signature, error) {
	right, err := ValidateRightId(rightHolderId, rightId)
	if err != nil {
		return nil, err
	}
	rightHolderIds := spec.GetRightHolderIds(right)
	for i := range rightHolderIds {
		if rightHolderId == rightHolderIds[i] {
			tx, err := bigchain.HttpGetTx(rightHolderId)
			if err != nil {
				return nil, err
			}
			rightHolderKey := bigchain.DefaultGetTxSender(tx)
			if rightHolderKey.Equals(priv.Public()) {
				hash, err := DefaultBalloonHash(challenge)
				if err != nil {
					return nil, err
				}
				return priv.Sign(hash), nil
			}
		}
	}
	return nil, ErrorAppend(ErrInvalidId, "could not match rightHolderId")
}

func VerifyRightHolder(challenge string, rightHolderId, rightId string, sig crypto.Signature) error {
	right, err := ValidateRightId(rightHolderId, rightId)
	if err != nil {
		return err
	}
	rightHolderIds := spec.GetRightHolderIds(right)
	for i := range rightHolderIds {
		if rightHolderId == rightHolderIds[i] {
			tx, err := bigchain.HttpGetTx(rightHolderId)
			if err != nil {
				return err
			}
			rightHolderKey := bigchain.DefaultGetTxSender(tx)
			hash, err := DefaultBalloonHash(challenge)
			if err != nil {
				return err
			}
			if !rightHolderKey.Verify(hash, sig) {
				return ErrorAppend(ErrInvalidSignature, sig.String())
			}
			return nil
		}
	}
	return ErrorAppend(ErrInvalidId, "id does not match right-holder id")
}

func ValidateLicenseId(licenseId string) (Data, error) {
	tx, err := QueryAndValidateSchema(licenseId, "license")
	if err != nil {
		return nil, err
	}
	license := bigchain.GetTxData(tx)
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	licenserId := spec.GetLicenserId(license)
	licenserKey := bigchain.DefaultGetTxSender(tx)
	outputs := bigchain.GetTxOutputs(tx)
OUTER_1:
	for _, licenseHolderId := range licenseHolderIds {
		if licenserId == licenseHolderId {
			return nil, Error("licenser cannot be license-holder")
		}
		tx, err := QueryAndValidateSchema(licenseHolderId, "user")
		if err != nil {
			return nil, err
		}
		licenseHolderKey := bigchain.DefaultGetTxSender(tx)
		for i, output := range outputs {
			if licenseHolderKey.Equals(bigchain.GetOutputPublicKey(output)) {
				outputs = append(outputs[:i], outputs[i+1:]...)
				continue OUTER_1
			}
		}
		return nil, Error("license-holder does not have output")
	}
	tx, err = QueryAndValidateSchema(licenserId, "user")
	if err != nil {
		return nil, err
	}
	if !licenserKey.Equals(bigchain.DefaultGetTxSender(tx)) {
		return nil, ErrorAppend(ErrInvalidKey, licenserKey.String())
	}
	licenseFor := spec.GetLicenseFor(license)
OUTER_2:
	for i := range licenseFor {
		licenseForId := spec.GetId(licenseFor[i])
		tx, err = bigchain.HttpGetTx(licenseForId)
		if err != nil {
			return nil, err
		}
		licensed := bigchain.GetTxData(tx)
		licensedType := spec.GetType(licensed)
		outputs := bigchain.GetTxOutputs(tx)
		if licensedType == "MusicComposition" {
			_, err = ValidateComposition(licensed, outputs)
		} else if licensedType == "MusicRecording" {
			_, err = ValidateRecording(outputs, licensed)
		} else {
			return nil, ErrorAppend(ErrInvalidType, "Expected MusicComposition or MusicRecording; got "+licensedType)
		}
		if err != nil {
			return nil, err
		}
		rightId := spec.GetRightId(licenseFor[i])
		if !EmptyStr(rightId) {
			right, err := ValidateRightId(licenserId, rightId)
			if err != nil {
				return nil, err
			}
			if licenseForId != spec.GetRightToId(right) {
				return nil, ErrorAppend(ErrInvalidId, "right has wrong compositionId/recordingId")
			}
			rightHolderIds := spec.GetRightHolderIds(right)
			for _, rightHolderId := range rightHolderIds {
				if licenserId == rightHolderId {
					continue OUTER_2
				}
			}
		} else {
			if licensedType == "MusicComposition" {
				composers := spec.GetComposers(licensed)
				for _, composer := range composers {
					if licenserId != spec.GetId(composer) {
						continue OUTER_2
					}
				}
			}
			if licensedType == "MusicRecording" {
				artists := spec.GetArtists(licensed)
				for _, artist := range artists {
					if licenserId != spec.GetId(artist) {
						continue OUTER_2
					}
				}
			}
		}
		return nil, Error("licenser is not artist/composer or right-holder")
	}
	return license, nil
}

func ProveLicenseHolder(challenge, licenseHolderId, licenseId string, priv crypto.PrivateKey) (crypto.Signature, error) {
	license, err := ValidateLicenseId(licenseId)
	if err != nil {
		return nil, err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	for i := range licenseHolderIds {
		if licenseHolderId == licenseHolderIds[i] {
			tx, err := bigchain.HttpGetTx(licenseHolderId)
			if err != nil {
				return nil, err
			}
			licenseHolderKey := bigchain.DefaultGetTxSender(tx)
			if pub := priv.Public(); !licenseHolderKey.Equals(pub) {
				return nil, ErrorAppend(ErrInvalidKey, pub.String())
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
	license, err := ValidateLicenseId(licenseId)
	if err != nil {
		return err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	for i := range licenseHolderIds {
		if licenseHolderId == licenseHolderIds[i] {
			tx, err := bigchain.HttpGetTx(licenseHolderId)
			if err != nil {
				return err
			}
			licenseHolderKey := bigchain.DefaultGetTxSender(tx)
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

func ValidateRecordingId(recordingId string) (Data, error) {
	tx, err := bigchain.HttpGetTx(recordingId)
	if err != nil {
		return nil, err
	}
	recording := bigchain.GetTxData(tx)
	outputs := bigchain.GetTxOutputs(tx)
	return ValidateRecording(outputs, recording)
}

func ValidateRecording(outputs []Data, recording Data) (Data, error) {
	if err := schema.ValidateSchema(recording, "recording"); err != nil {
		return nil, err
	}
	artists := spec.GetArtists(recording)
	n := len(artists)
	if n != len(outputs) {
		return nil, Error("number of outputs doesn't equal number of artists")
	}
	recordingOf := spec.GetRecordingOf(recording)
	compositionId := spec.GetId(recordingOf)
	composition, err := ValidateCompositionId(compositionId)
	if err != nil {
		return nil, err
	}
	var licenseHolderIds []string
	licenseId := spec.GetLicenseId(recordingOf)
	if !EmptyStr(licenseId) {
		license, err := ValidateLicenseId(licenseId)
		if err != nil {
			return nil, err
		}
		licenseFor := spec.GetLicenseFor(license)
		for i := range licenseFor {
			if compositionId == spec.GetId(licenseFor[i]) {
				licenseHolderIds = spec.GetLicenseHolderIds(license)
				goto NEXT
			}
		}
		return nil, ErrorAppend(ErrInvalidId, "license does not have compositionId")
	}
NEXT:
	artistKeys := make([]crypto.PublicKey, n)
	composers := spec.GetComposers(composition)
	totalShares := 0
OUTER:
	for i, artist := range artists {
		// TODO: check for repeat pubkeys
		artistId := spec.GetId(artist)
		tx, err := QueryAndValidateSchema(artistId, "user")
		if err != nil {
			return nil, err
		}
		artistKeys[i] = bigchain.DefaultGetTxSender(tx)
		for j, output := range outputs {
			if artistKeys[i].Equals(bigchain.GetOutputPublicKey(output)) {
				outputs = append(outputs[:j], outputs[j+1:]...)
				if totalShares += bigchain.GetOutputAmount(output); totalShares > 100 {
					return nil, Error("total shares exceed 100")
				}
				for k, composer := range composers {
					if artistId == spec.GetId(composer) {
						composers = append(composers[:k], composers[k+1:]...)
						continue OUTER
					}
				}
				if len(licenseHolderIds) > 0 {
					for k, licenseHolderId := range licenseHolderIds {
						if artistId == licenseHolderId {
							licenseHolderIds = append(licenseHolderIds[:k], licenseHolderIds[k+1:]...)
							continue OUTER
						}
					}
				}
				return nil, Error("artist is not composer/does not have mechanical license")
			}
		}
		return nil, Error("could not find output with artist pubkey")
	}
	if totalShares != 100 {
		return nil, Error("total shares do not equal 100")
	}
	if n > 1 {
		thresholdSignature := spec.GetURI(recording)
		ful, err := cc.DefaultUnmarshalURI(thresholdSignature)
		if err != nil {
			return nil, err
		}
		thresholdFulfillment := cc.DefaultFulfillmentThresholdFromPubKeys(artistKeys)
		if cc.GetCondition(ful).String() != cc.GetCondition(thresholdFulfillment).String() {
			return nil, ErrInvalidCondition
		}
		recording.Delete("thresholdSignature")
		buf := new(bytes.Buffer)
		checksum := Checksum256(MustMarshalJSON(recording))
		for i := 0; i < n; i++ {
			WriteVarOctet(buf, checksum)
		}
		if !ful.Validate(buf.Bytes()) {
			return nil, ErrorAppend(ErrInvalidFulfillment, ful.String())
		}
		recording.Set("thresholdSignature", thresholdSignature)
	}
	recordLabelId := spec.GetRecordLabelId(recording)
	if !EmptyStr(recordLabelId) {
		if _, err = QueryAndValidateSchema(recordLabelId, "user"); err != nil {
			return nil, err
		}
		for i, licenseHolderId := range licenseHolderIds {
			if recordLabelId == licenseHolderId {
				licenseHolderIds = append(licenseHolderIds[:i], licenseHolderIds[i+1:]...)
				goto END
			}
		}
		return nil, ErrorAppend(ErrInvalidId, "wrong licenseHolderId")
	}
END:
	return recording, nil
}

func ProveArtist(artistId, challenge string, priv crypto.PrivateKey, recordingId string) (crypto.Signature, error) {
	recording, err := ValidateRecordingId(recordingId)
	if err != nil {
		return nil, err
	}
	artists := spec.GetArtists(recording)
	for _, artist := range artists {
		if artistId == spec.GetId(artist) {
			tx, err := bigchain.HttpGetTx(artistId)
			if err != nil {
				return nil, err
			}
			if pub := priv.Public(); !pub.Equals(bigchain.DefaultGetTxSender(tx)) {
				return nil, ErrorAppend(ErrInvalidKey, pub.String())
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

func VerifyArtist(artistId, challenge, recordingId string, sig crypto.Signature) error {
	recording, err := ValidateRecordingId(recordingId)
	if err != nil {
		return err
	}
	artists := spec.GetArtists(recording)
	for _, artist := range artists {
		if artistId == spec.GetId(artist) {
			tx, err := bigchain.HttpGetTx(artistId)
			if err != nil {
				return err
			}
			artistKey := bigchain.DefaultGetTxSender(tx)
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

func ValidateReleaseId(releaseId string) (Data, error) {
	tx, err := QueryAndValidateSchema(releaseId, "release")
	if err != nil {
		return nil, err
	}
	release := bigchain.GetTxData(tx)
	recordLabelId := spec.GetRecordLabelId(release)
	recordLabelKey := bigchain.DefaultGetTxSender(tx)
	tx, err = QueryAndValidateSchema(recordLabelId, "user")
	if err != nil {
		return nil, err
	}
	if !recordLabelKey.Equals(bigchain.DefaultGetTxSender(tx)) {
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
	pubkey := bigchain.DefaultGetTxSender(tx)
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
	pubkey := bigchain.DefaultGetTxSender(tx)
	if !pubkey.Verify(hash, sig) {
		return ErrorAppend(ErrInvalidSignature, sig.String())
	}
	return nil
}
