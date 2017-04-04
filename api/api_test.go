package api

import (
	"testing"

	"github.com/zbo14/envoke/bigchain"
	. "github.com/zbo14/envoke/common"
	"github.com/zbo14/envoke/crypto/crypto"
	"github.com/zbo14/envoke/crypto/ed25519"
	ld "github.com/zbo14/envoke/linked_data"
	"github.com/zbo14/envoke/spec"
)

var CHALLENGE = "Y2hhbGxlbmdl"

func GetId(data Data) string {
	return data.GetStr("id")
}

func GetPrivateKey(data Data) crypto.PrivateKey {
	privkey := new(ed25519.PrivateKey)
	privkey.FromString(data.GetStr("privateKey"))
	return privkey
}

func GetUserId(data Data) string {
	return data.GetStr("userId")
}

func TestApi(t *testing.T) {
	api := NewApi()
	output := MustOpenWriteFile("output.json")
	composer, err := api.Register(
		"itisasecret",
		spec.NewUser("composer@email.com", "", "", nil, "composer", "", "www.composer.com", "Person"),
	)
	if err != nil {
		t.Fatal(err)
	}
	composerId := GetUserId(composer)
	composerPrivKey := GetPrivateKey(composer)
	WriteJSON(output, composer)
	recordLabel, err := api.Register(
		"shhhh",
		spec.NewUser("record_label@email.com", "", "", nil, "record_label", "", "www.record_label.com", "Organization"),
	)
	if err != nil {
		t.Fatal(err)
	}
	recordLabelId := GetUserId(recordLabel)
	recordLabelPrivKey := GetPrivateKey(recordLabel)
	WriteJSON(output, recordLabel)
	performer, err := api.Register(
		"makeitup",
		spec.NewUser("performer@email.com", "123456789", "", nil, "performer", "ASCAP", "www.performer.com", "MusicGroup"),
	)
	if err != nil {
		t.Fatal(err)
	}
	performerId := GetUserId(performer)
	performerPrivKey := GetPrivateKey(performer)
	WriteJSON(output, performer)
	producer, err := api.Register(
		"1234",
		spec.NewUser("producer@email.com", "", "", nil, "producer", "", "www.soundcloud_page.com", "Person"),
	)
	if err != nil {
		t.Fatal(err)
	}
	producerId := GetUserId(producer)
	producerPrivKey := GetPrivateKey(producer)
	WriteJSON(output, producer)
	publisher, err := api.Register(
		"didyousaysomething?",
		spec.NewUser("publisher@email.com", "", "", nil, "publisher", "", "www.publisher.com", "Organization"),
	)
	if err != nil {
		t.Fatal(err)
	}
	publisherId := GetUserId(publisher)
	publisherPrivKey := GetPrivateKey(publisher)
	WriteJSON(output, publisher)
	radio, err := api.Register(
		"waves",
		spec.NewUser("radio@email.com", "", "", nil, "radio", "", "www.radio_station.com", "Organization"),
	)
	if err != nil {
		t.Fatal(err)
	}
	radioId := GetUserId(radio)
	radioPrivKey := GetPrivateKey(radio)
	WriteJSON(output, radio)
	if err := api.Login(composerPrivKey.String(), composerId); err != nil {
		t.Fatal(err)
	}
	composition, err := spec.NewComposition([]string{composerId}, "T-034.524.680-1", "EN", "composition_title", publisherId, "www.composition_url.com")
	if err != nil {
		t.Fatal(err)
	}
	composition, err = api.Compose(composition, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	compositionId := GetId(composition)
	WriteJSON(output, composition)
	sig, err := ld.ProveComposer(CHALLENGE, composerId, compositionId, composerPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyComposer(CHALLENGE, composerId, compositionId, sig); err != nil {
		t.Fatal(err)
	}
	SleepSeconds(2)
	rightHolderIds, transferId, err := api.Transfer(compositionId, compositionId, publisherPrivKey.Public(), publisherId, 20)
	if err != nil {
		t.Fatal(err)
	}
	compositionRight, err := spec.NewRight(rightHolderIds, compositionId, transferId)
	if err != nil {
		t.Fatal(err)
	}
	compositionRight, err = api.SendMultipleOwnersCreateTx([]int{1, 1}, compositionRight, []crypto.PublicKey{composerPrivKey.Public(), publisherPrivKey.Public()})
	if err != nil {
		t.Fatal(err)
	}
	compositionRightId := GetId(compositionRight)
	WriteJSON(output, compositionRight)
	sig, err = ld.ProveRightHolder(CHALLENGE, composerPrivKey, composerId, compositionRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, composerId, compositionRightId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveRightHolder(CHALLENGE, publisherPrivKey, publisherId, compositionRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, publisherId, compositionRightId, sig); err != nil {
		t.Fatal(err)
	}
	if err = api.Login(publisherPrivKey.String(), publisherId); err != nil {
		t.Fatal(err)
	}
	mechanicalLicense, err := spec.NewLicense([]string{compositionId}, []string{performerId, producerId, recordLabelId}, publisherId, []string{compositionRightId}, "2020-01-01", "2024-01-01")
	if err != nil {
		t.Fatal(err)
	}
	mechanicalLicense, err = api.SendMultipleOwnersCreateTx([]int{1, 1, 1}, mechanicalLicense, []crypto.PublicKey{performerPrivKey.Public(), producerPrivKey.Public(), recordLabelPrivKey.Public()})
	if err != nil {
		t.Fatal(err)
	}
	mechanicalLicenseId := GetId(mechanicalLicense)
	WriteJSON(output, mechanicalLicense)
	sig, err = ld.ProveLicenseHolder(CHALLENGE, performerId, mechanicalLicenseId, performerPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, performerId, mechanicalLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveLicenseHolder(CHALLENGE, producerId, mechanicalLicenseId, producerPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, producerId, mechanicalLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveLicenseHolder(CHALLENGE, recordLabelId, mechanicalLicenseId, recordLabelPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, recordLabelId, mechanicalLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	/*
		transferId, err = api.Transfer(compositionId, transferId, composerPrivKey.Public(), 10)
		if err != nil {
			t.Fatal(err)
		}
		compositionRight, err = api.DefaultSendIndividualCreateTx(spec.NewCompositionRight([]string{publisherId, composerId}, compositionId, transferId))
		if err != nil {
			t.Fatal(err)
		}
		WriteJSON(output, compositionRight)
		if _, err = ld.ValidateRight(publisherId, compositionRightId); err == nil {
			t.Error("TRANSFER tx output should be spent")
		} else {
			t.Log(err.Error())
		}
	*/
	file, err := OpenFile(Getenv("PATH_TO_AUDIO_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	if err = api.Login(performerPrivKey.String(), performerId); err != nil {
		t.Fatal(err)
	}
	signRecording, err := spec.NewRecording([]string{performerId, producerId}, compositionId, "PT2M43S", "US-S1Z-99-00001", mechanicalLicenseId, recordLabelId, "www.recording_url.com")
	if err != nil {
		t.Fatal(err)
	}
	recording, err := api.Record(file, []int{80, 20}, signRecording, nil)
	if err != nil {
		t.Fatal(err)
	}
	recordingId := GetId(recording)
	performerSig := api.Sign(signRecording)
	if err = api.Login(producerPrivKey.String(), producerId); err != nil {
		t.Fatal(err)
	}
	producerSig := api.Sign(signRecording)
	if err = api.Login(performerPrivKey.String(), performerId); err != nil {
		t.Fatal(err)
	}
	recording, err = api.Record(file, []int{80, 20}, signRecording, []string{performerSig.String(), producerSig.String()})
	if err != nil {
		t.Fatal(err)
	}
	recordingId = GetId(recording)
	WriteJSON(output, recording)
	SleepSeconds(2)
	sig, err = ld.ProveArtist(performerId, CHALLENGE, performerPrivKey, recordingId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyArtist(performerId, CHALLENGE, recordingId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveArtist(producerId, CHALLENGE, producerPrivKey, recordingId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyArtist(producerId, CHALLENGE, recordingId, sig); err != nil {
		t.Fatal(err)
	}
	rightHolderIds, transferId, err = api.Transfer(recordingId, recordingId, recordLabelPrivKey.Public(), recordLabelId, 20)
	if err != nil {
		t.Fatal(err)
	}
	recordingRight, err := spec.NewRight(rightHolderIds, recordingId, transferId)
	if err != nil {
		t.Fatal(err)
	}
	recordingRight, err = api.SendMultipleOwnersCreateTx([]int{1, 1}, recordingRight, []crypto.PublicKey{performerPrivKey.Public(), recordLabelPrivKey.Public()})
	if err != nil {
		t.Fatal(err)
	}
	recordingRightId := GetId(recordingRight)
	WriteJSON(output, recordingRight)
	sig, err = ld.ProveRightHolder(CHALLENGE, performerPrivKey, performerId, recordingRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, performerId, recordingRightId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveRightHolder(CHALLENGE, recordLabelPrivKey, recordLabelId, recordingRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, recordLabelId, recordingRightId, sig); err != nil {
		t.Fatal(err)
	}
	if err = api.Login(recordLabelPrivKey.String(), recordLabelId); err != nil {
		t.Fatal(err)
	}
	/*
		release, err := api.DefaultSendIndividualCreateTx(spec.NewRelease("release_title", []string{recordingId}, recordLabelId, []string{recordingRightId}, "www.release_url.com"))
		if err != nil {
			t.Fatal(err)
		}
		releaseId := GetId(release)
		WriteJSON(output, release)
		sig, err = ld.ProveRecordLabel(CHALLENGE, recordLabelPrivKey, releaseId)
		if err != nil {
			t.Fatal(err)
		}
		if err = ld.VerifyRecordLabel(CHALLENGE, releaseId, sig); err != nil {
			t.Fatal(err)
		}
	*/
	masterLicense, err := spec.NewLicense([]string{recordingId}, []string{radioId}, recordLabelId, []string{recordingRightId}, "2020-01-01", "2022-01-01")
	if err != nil {
		t.Fatal(err)
	}
	masterLicense, err = api.SendIndividualCreateTx(1, masterLicense, radioPrivKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	masterLicenseId := GetId(masterLicense)
	WriteJSON(output, masterLicense)
	sig, err = ld.ProveLicenseHolder(CHALLENGE, radioId, masterLicenseId, radioPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, radioId, masterLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	txs, err := bigchain.HttpGetFilter(func(txId string) (Data, error) {
		return ld.ValidateCompositionId(txId)
	}, composerPrivKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	PrintJSON(txs)
}
