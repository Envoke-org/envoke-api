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
	tx, err := bigchain.GetTx(id)
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

func ValidateComposition(compositionId string) (Data, error) {
	tx, err := QueryAndValidateSchema(compositionId, "composition")
	if err != nil {
		return nil, err
	}
	composition := bigchain.GetTxData(tx)
	composers := spec.GetComposers(composition)
	n := len(composers)
	outputs := bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return nil, ErrorAppend(ErrCriteriaNotMet, "number of outputs doesn't equal number of composers")
	}
	composerKeys := make([]crypto.PublicKey, n)
	totalShares := 0
OUTER:
	for i, composer := range composers {
		// TODO: check pubkeys
		tx, err = QueryAndValidateSchema(spec.GetId(composer), "party")
		if err != nil {
			return nil, err
		}
		composerKeys[i] = bigchain.DefaultGetTxSender(tx)
		for i, output := range outputs {
			if composerKeys[i].Equals(bigchain.DefaultGetTxRecipient(tx)) {
				outputs = append(outputs[:i], outputs[i+1:]...)
				if totalShares += bigchain.GetOutputAmount(output); totalShares > 100 {
					return nil, ErrorAppend(ErrCriteriaNotMet, "total shares exceed 100")
				}
				continue OUTER
			}
		}
		return nil, ErrorAppend(ErrCriteriaNotMet, "could not find output with composer pubkey")
	}
	if totalShares != 100 {
		return nil, ErrorAppend(ErrCriteriaNotMet, "total shares do not equal 100")
	}
	if n > 1 {
		uri := spec.GetURI(composition)
		ful, err := cc.DefaultUnmarshalURI(uri)
		if err != nil {
			return nil, err
		}
		thresh := cc.DefaultFulfillmentThresholdFromPubKeys(composerKeys)
		if cc.GetCondition(ful).String() != cc.GetCondition(thresh).String() {
			return nil, ErrInvalidCondition
		}
		composition.Delete("uri")
		buf := new(bytes.Buffer)
		checksum := Checksum256(MustMarshalJSON(composition))
		for i := 0; i < n; i++ {
			WriteVarOctet(buf, checksum)
		}
		if !ful.Validate(buf.Bytes()) {
			return nil, ErrorAppend(ErrInvalidFulfillment, ful.String())
		}
		composition.Set("uri", uri)
	}
	return composition, nil
}

func ProveComposer(challenge, composerId, compositionId string, priv crypto.PrivateKey) (crypto.Signature, error) {
	composition, err := ValidateComposition(compositionId)
	if err != nil {
		return nil, err
	}
	composers := spec.GetComposers(composition)
	for _, composer := range composers {
		if composerId == spec.GetId(composer) {
			tx, err := bigchain.GetTx(composerId)
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
	composition, err := ValidateComposition(compositionId)
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
	tx, err := bigchain.GetTx(composerId)
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

func ValidateRight(rightId string) (Data, error) {
	tx, err := QueryAndValidateSchema(rightId, "right")
	if err != nil {
		return nil, err
	}
	right := bigchain.GetTxData(tx)
	rightHolderIds := spec.GetRightHolderIds(right)
	n := len(rightHolderIds)
	if n != 1 && n != 2 {
		return nil, ErrorAppend(ErrInvalidSize, "rightHolderIds must have size 1 or 2")
	}
	var recipientKey crypto.PublicKey = nil
	senderKey := bigchain.DefaultGetTxSender(tx)
	for _, rightHolderId := range rightHolderIds {
		tx, err = QueryAndValidateSchema(rightHolderId, "party")
		if err != nil {
			return nil, err
		}
		rightHolderKey := bigchain.DefaultGetTxSender(tx)
		if senderKey.Equals(rightHolderKey) {
			if n == 1 {
				return nil, ErrorAppend(ErrCriteriaNotMet, "sender key equals right-holder key")
			}
		} else {
			if recipientKey != nil {
				return nil, ErrorAppend(ErrCriteriaNotMet, "sender is not second right-holder")
			}
			recipientKey = rightHolderKey
		}
	}
	rightToId := spec.GetRightToId(right)
	if _type := spec.GetType(right); _type == "CompositionRight" {
		_, err = ValidateComposition(rightToId)
	} else if _type == "RecordingRight" {
		_, err = ValidateRecording(rightToId)
	} else {
		return nil, ErrorAppend(ErrInvalidType, _type)
	}
	if err != nil {
		return nil, err
	}
	transferId := spec.GetTransferId(right)
	tx, err = bigchain.GetTx(transferId)
	if err != nil {
		return nil, err
	}
	if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
		return nil, ErrorAppend(ErrCriteriaNotMet, "expected TRANSFER tx")
	}
	if !senderKey.Equals(bigchain.DefaultGetTxSender(tx)) {
		return nil, ErrorAppend(ErrCriteriaNotMet, "right sender is not sender of TRANSFER tx")
	}
	if n != len(bigchain.GetTxOutputs(tx)) {
		return nil, ErrorAppend(ErrInvalidSize, "TRANSFER tx outputs must have same size as rightHolderIds")
	}
	if !recipientKey.Equals(bigchain.GetTxRecipient(tx, 1)) {
		return nil, ErrorAppend(ErrCriteriaNotMet, "recipient does not hold secondary output of TRANSFER tx")
	}
	recipientShares := bigchain.GetTxOutputAmount(tx, 1)
	if recipientShares <= 0 || recipientShares > 100 {
		return nil, ErrorAppend(ErrCriteriaNotMet, "recipient shares must be greater than 0 and less than/equal to 100")
	}
	right.Set("recipientShares", recipientShares)
	if n == 2 {
		if !senderKey.Equals(bigchain.GetTxRecipient(tx, 0)) {
			return nil, ErrorAppend(ErrCriteriaNotMet, "sender does not hold primary output of TRANSFER tx")
		}
		senderShares := bigchain.GetTxOutputAmount(tx, 0)
		if senderShares < 0 || senderShares > 100 {
			return nil, ErrorAppend(ErrCriteriaNotMet, "sender shares cannot be less than 0 or greater than 100")
		}
		right.Set("senderShares", senderShares)
	}
	if rightToId != bigchain.GetTxAssetId(tx) {
		return nil, ErrorAppend(ErrCriteriaNotMet, "TRANSFER tx does not link to composition")
	}
	return right, nil
}

func ProveRightHolder(challenge string, priv crypto.PrivateKey, rightHolderId, rightId string) (crypto.Signature, error) {
	right, err := ValidateRight(rightId)
	if err != nil {
		return nil, err
	}
	rightHolderIds := spec.GetRightHolderIds(right)
	for i := range rightHolderIds {
		if rightHolderId == rightHolderIds[i] {
			tx, err := bigchain.GetTx(rightHolderId)
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

func VerifyRightHolder(challenge, rightHolderId, rightId string, sig crypto.Signature) error {
	right, err := ValidateRight(rightId)
	if err != nil {
		return err
	}
	rightHolderIds := spec.GetRightHolderIds(right)
	for i := range rightHolderIds {
		if rightHolderId == rightHolderIds[i] {
			tx, err := bigchain.GetTx(rightHolderId)
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

func ValidateLicense(licenseId string) (Data, error) {
	tx, err := QueryAndValidateSchema(licenseId, "license")
	if err != nil {
		return nil, err
	}
	license := bigchain.GetTxData(tx)
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	licenserId := spec.GetLicenserId(license)
	licenserKey := bigchain.DefaultGetTxSender(tx)
	licenseType := spec.GetType(license)
	if licenseType != "MasterLicense" && licenseType != "MechanicalLicense" {
		return nil, ErrorAppend(ErrInvalidType, licenseType)
	}
	for _, licenseHolderId := range licenseHolderIds {
		// TODO: check pubkeys
		if licenserId == licenseHolderId {
			return nil, ErrorAppend(ErrCriteriaNotMet, "licenser cannot be licenseHolder")
		}
		tx, err = QueryAndValidateSchema(licenseHolderId, "party")
		if err != nil {
			return nil, err
		}
	}
	tx, err = QueryAndValidateSchema(licenserId, "party")
	if err != nil {
		return nil, err
	}
	if !licenserKey.Equals(bigchain.DefaultGetTxSender(tx)) {
		return nil, ErrorAppend(ErrInvalidKey, licenserKey.String())
	}
	licenseFor := spec.GetLicenseFor(license)
OUTER:
	for i := range licenseFor {
		licenseForId := spec.GetId(licenseFor[i])
		var licensed Data
		if licenseType == "MasterLicense" {
			licensed, err = ValidateRecording(licenseForId)
		}
		if licenseType == "MechanicalLicense" {
			licensed, err = ValidateComposition(licenseForId)
		}
		if err != nil {
			return nil, err
		}
		rightId := spec.GetRightId(licenseFor[i])
		if !EmptyStr(rightId) {
			right, err := ValidateRight(rightId)
			if err != nil {
				return nil, err
			}
			if licenseForId != spec.GetRightToId(right) {
				return nil, ErrorAppend(ErrInvalidId, "right has wrong compositionId/recordingId")
			}
			rightHolderIds := spec.GetRightHolderIds(right)
			for _, rightHolderId := range rightHolderIds {
				if licenserId == rightHolderId {
					continue OUTER
				}
			}
		} else {
			if licenseType == "MasterLicense" {
				artists := spec.GetArtists(licensed)
				for _, artist := range artists {
					if licenserId != spec.GetId(artist) {
						continue OUTER
					}
				}
			}
			if licenseType == "MechanicalLicense" {
				composers := spec.GetComposers(licensed)
				for _, composer := range composers {
					if licenserId != spec.GetId(composer) {
						continue OUTER
					}
				}
			}
		}
		return nil, ErrorAppend(ErrCriteriaNotMet, "licenser is not artist/composer or right-holder")
	}
	return license, nil
}

func ProveLicenseHolder(challenge, licenseHolderId, licenseId string, priv crypto.PrivateKey) (crypto.Signature, error) {
	license, err := ValidateLicense(licenseId)
	if err != nil {
		return nil, err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	for i := range licenseHolderIds {
		if licenseHolderId == licenseHolderIds[i] {
			tx, err := bigchain.GetTx(licenseHolderId)
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
	license, err := ValidateLicense(licenseId)
	if err != nil {
		return err
	}
	licenseHolderIds := spec.GetLicenseHolderIds(license)
	for i := range licenseHolderIds {
		if licenseHolderId == licenseHolderIds[i] {
			tx, err := bigchain.GetTx(licenseHolderId)
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

func ValidateRecording(recordingId string) (Data, error) {
	tx, err := QueryAndValidateSchema(recordingId, "recording")
	if err != nil {
		return nil, err
	}
	recording := bigchain.GetTxData(tx)
	compositionId := spec.GetRecordingOfId(recording)
	composition, err := QueryAndValidateSchema(compositionId, "composition")
	if err != nil {
		return nil, err
	}
	composers := spec.GetComposers(composition)
	artists := spec.GetArtists(recording)
	n := len(artists)
	outputs := bigchain.GetTxOutputs(tx)
	if n != len(outputs) {
		return nil, ErrorAppend(ErrCriteriaNotMet, "number of outputs doesn't equal number of artists")
	}
	artistKeys := make([]crypto.PublicKey, n)
	totalShares := 0
OUTER:
	for i, artist := range artists {
		// TODO: check pubkeys
		artistId := spec.GetId(artist)
		tx, err = QueryAndValidateSchema(artistId, "party")
		if err != nil {
			return nil, err
		}
		artistKeys[i] = bigchain.DefaultGetTxSender(tx)
		for j, output := range outputs {
			if artistKeys[i].Equals(bigchain.DefaultGetTxRecipient(tx)) {
				outputs = append(outputs[:j], outputs[j+1:]...)
				if totalShares += bigchain.GetOutputAmount(output); totalShares > 100 {
					return nil, ErrorAppend(ErrCriteriaNotMet, "total shares exceed 100")
				}
				licenseId := spec.GetLicenseId(artist)
				if !EmptyStr(licenseId) {
					license, err := ValidateLicense(licenseId)
					if err != nil {
						return nil, err
					}
					licenseFor := spec.GetLicenseFor(license)
					for _, composition := range licenseFor {
						if compositionId == spec.GetId(composition) {
							licenseHolderIds := spec.GetLicenseHolderIds(license)
							for _, licenseHolderId := range licenseHolderIds {
								if artistId == licenseHolderId {
									continue OUTER
								}
							}
							return nil, ErrorAppend(ErrInvalidId, "wrong licenseHolderId")
						}
					}
					return nil, ErrorAppend(ErrInvalidId, "mechanical license does not have compositionId")
				} else {
					for _, composer := range composers {
						if artistId == spec.GetId(composer) {
							continue OUTER
						}
					}
					return nil, ErrorAppend(ErrCriteriaNotMet, "artist is not composer/does not have mechanical")
				}
			}
		}
		return nil, ErrorAppend(ErrCriteriaNotMet, "could not find output with composer pubkey")
	}
	if totalShares != 100 {
		return nil, ErrorAppend(ErrCriteriaNotMet, "total shares do not equal 100")
	}
	if n > 1 {
		uri := spec.GetURI(recording)
		ful, err := cc.DefaultUnmarshalURI(uri)
		if err != nil {
			return nil, err
		}
		thresh := cc.DefaultFulfillmentThresholdFromPubKeys(artistKeys)
		if cc.GetCondition(ful).String() != cc.GetCondition(thresh).String() {
			return nil, ErrInvalidCondition
		}
		recording.Delete("uri")
		buf := new(bytes.Buffer)
		checksum := Checksum256(MustMarshalJSON(recording))
		for i := 0; i < n; i++ {
			WriteVarOctet(buf, checksum)
		}
		if !ful.Validate(buf.Bytes()) {
			return nil, ErrorAppend(ErrInvalidFulfillment, ful.String())
		}
		recording.Set("uri", uri)
	}
	return recording, nil
}

func ProveArtist(artistId, challenge string, priv crypto.PrivateKey, recordingId string) (crypto.Signature, error) {
	recording, err := ValidateRecording(recordingId)
	if err != nil {
		return nil, err
	}
	artists := spec.GetArtists(recording)
	for _, artist := range artists {
		if artistId == spec.GetId(artist) {
			tx, err := bigchain.GetTx(artistId)
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
	recording, err := ValidateRecording(recordingId)
	if err != nil {
		return err
	}
	artists := spec.GetArtists(recording)
	for _, artist := range artists {
		if artistId == spec.GetId(artist) {
			tx, err := bigchain.GetTx(artistId)
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

func ValidateRelease(releaseId string) (Data, error) {
	tx, err := QueryAndValidateSchema(releaseId, "release")
	if err != nil {
		return nil, err
	}
	release := bigchain.GetTxData(tx)
	recordLabelId := spec.GetRecordLabelId(release)
	recordLabelKey := bigchain.DefaultGetTxSender(tx)
	tx, err = QueryAndValidateSchema(recordLabelId, "party")
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
		if _, err := ValidateRecording(recordingId); err != nil {
			return nil, err
		}
		rightId := spec.GetRightId(recording)
		right, err := ValidateRight(rightId)
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
		return nil, ErrorAppend(ErrCriteriaNotMet, "recordLabel is not recording right-holder")
	}
	return release, nil
}

func ProveRecordLabel(challenge string, priv crypto.PrivateKey, releaseId string) (crypto.Signature, error) {
	release, err := ValidateRelease(releaseId)
	if err != nil {
		return nil, err
	}
	recordLabelId := spec.GetRecordLabelId(release)
	tx, err := bigchain.GetTx(recordLabelId)
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
	release, err := ValidateRelease(releaseId)
	if err != nil {
		return err
	}
	recordLabelId := spec.GetRecordLabelId(release)
	tx, err := bigchain.GetTx(recordLabelId)
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
