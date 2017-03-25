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

var (
	CHALLENGE = "Y2hhbGxlbmdl"
	DIR       = Getenv("DIR")
)

func GetId(data Data) string {
	return data.GetStr("id")
}

func GetPrivateKey(data Data) crypto.PrivateKey {
	priv := new(ed25519.PrivateKey)
	priv.FromString(data.GetStr("privateKey"))
	return priv
}

func TestApi(t *testing.T) {
	api := NewApi()
	output := MustOpenWriteFile("output.json")
	composer, err := api.Register(
		spec.NewParty("composer@email.com", "", "", nil, "composer", "", "www.composer.com", "Person"),
		"itisasecret",
		DIR+"composer",
	)
	if err != nil {
		t.Fatal(err)
	}
	composerId := GetId(composer)
	composerPriv := GetPrivateKey(composer)
	WriteJSON(output, composer)
	recordLabel, err := api.Register(
		spec.NewParty("record_label@email.com", "", "", nil, "record_label", "", "www.record_label.com", "Organization"),
		"shhhh",
		DIR+"record_label",
	)
	if err != nil {
		t.Fatal(err)
	}
	recordLabelId := GetId(recordLabel)
	recordLabelPriv := GetPrivateKey(recordLabel)
	WriteJSON(output, recordLabel)
	performer, err := api.Register(
		spec.NewParty("performer@email.com", "123456789", "", nil, "performer", "ASCAP", "www.performer.com", "MusicGroup"),
		"makeitup",
		DIR+"performer",
	)
	if err != nil {
		t.Fatal(err)
	}
	performerId := GetId(performer)
	performerPriv := GetPrivateKey(performer)
	WriteJSON(output, performer)
	producer, err := api.Register(
		spec.NewParty("producer@email.com", "", "", nil, "producer", "", "www.soundcloud_page.com", "Person"),
		"1234",
		DIR+"producer",
	)
	if err != nil {
		t.Fatal(err)
	}
	producerId := GetId(producer)
	producerPriv := GetPrivateKey(producer)
	WriteJSON(output, producer)
	publisher, err := api.Register(
		spec.NewParty("publisher@email.com", "", "", nil, "publisher", "", "www.publisher.com", "Organization"),
		"didyousaysomething?",
		DIR+"publisher",
	)
	if err != nil {
		t.Fatal(err)
	}
	publisherId := GetId(publisher)
	publisherPriv := GetPrivateKey(publisher)
	WriteJSON(output, publisher)
	radio, err := api.Register(
		spec.NewParty("radio@email.com", "", "", nil, "radio", "", "www.radio_station.com", "Organization"),
		"waves",
		DIR+"radio",
	)
	if err != nil {
		t.Fatal(err)
	}
	radioId := GetId(radio)
	radioPriv := GetPrivateKey(radio)
	WriteJSON(output, radio)
	if err := api.Login(composerId, composerPriv.String()); err != nil {
		t.Fatal(err)
	}
	composition, err := api.Compose(spec.NewComposition([]string{composerId}, "B3107S", "T-034.524.680-1", "EN", "composition_title", publisherId, nil, "www.url_to_composition.com", ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	compositionId := GetId(composition)
	WriteJSON(output, composition)
	sig, err := ld.ProveComposer(CHALLENGE, composerId, compositionId, composerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyComposer(CHALLENGE, composerId, compositionId, sig); err != nil {
		t.Fatal(err)
	}
	SleepSeconds(2)
	transferId, err := api.Transfer(compositionId, compositionId, 0, publisherPriv.Public(), 20)
	if err != nil {
		t.Fatal(err)
	}
	compositionRight, err := api.DefaultSendIndividualCreateTx(spec.NewCompositionRight([]string{composerId, publisherId}, compositionId, transferId))
	if err != nil {
		t.Fatal(err)
	}
	compositionRightId := GetId(compositionRight)
	WriteJSON(output, compositionRight)
	sig, err = ld.ProveRightHolder(CHALLENGE, composerPriv, composerId, compositionRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, composerId, compositionRightId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveRightHolder(CHALLENGE, publisherPriv, publisherId, compositionRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, publisherId, compositionRightId, sig); err != nil {
		t.Fatal(err)
	}
	if err = api.Login(publisherId, publisherPriv.String()); err != nil {
		t.Fatal(err)
	}
	mechanicalLicense, err := api.DefaultSendIndividualCreateTx(spec.NewMechanicalLicense([]string{compositionId}, []string{performerId, producerId, recordLabelId}, publisherId, []string{compositionRightId}, "2020-01-01", "2024-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	mechanicalLicenseId := GetId(mechanicalLicense)
	WriteJSON(output, mechanicalLicense)
	sig, err = ld.ProveLicenseHolder(CHALLENGE, performerId, mechanicalLicenseId, performerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, performerId, mechanicalLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveLicenseHolder(CHALLENGE, producerId, mechanicalLicenseId, producerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, producerId, mechanicalLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveLicenseHolder(CHALLENGE, recordLabelId, mechanicalLicenseId, recordLabelPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, recordLabelId, mechanicalLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	/*
		transferId, err = api.Transfer(compositionId, transferId, 1, composerPriv.Public(), 10)
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
	if err = api.Login(performerId, performerPriv.String()); err != nil {
		t.Fatal(err)
	}
	signRecording := spec.NewRecording([]string{performerId, producerId}, compositionId, "PT2M43S", "US-S1Z-99-00001", mechanicalLicenseId, []string{mechanicalLicenseId, mechanicalLicenseId}, recordLabelId, []string{"performer", "producer"}, "www.url_to_recording.com", "")
	recording, err := api.Record(file, []int{80, 20}, signRecording)
	if err != nil {
		t.Fatal(err)
	}
	recordingId := GetId(recording)
	performerFul, err := api.Sign(recordingId)
	if err != nil {
		t.Fatal(err)
	}
	if err = api.Login(producerId, producerPriv.String()); err != nil {
		t.Fatal(err)
	}
	producerFul, err := api.Sign(recordingId)
	if err != nil {
		t.Fatal(err)
	}
	if err = api.Login(performerId, performerPriv.String()); err != nil {
		t.Fatal(err)
	}
	thresh, err := Threshold([]string{performerFul.String(), producerFul.String()})
	if err != nil {
		t.Fatal(err)
	}
	signRecording.Set("uri", thresh.String())
	recording, err = api.Record(file, []int{80, 20}, signRecording)
	if err != nil {
		t.Fatal(err)
	}
	recordingId = GetId(recording)
	WriteJSON(output, recording)
	SleepSeconds(2)
	sig, err = ld.ProveArtist(performerId, CHALLENGE, performerPriv, recordingId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyArtist(performerId, CHALLENGE, recordingId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveArtist(producerId, CHALLENGE, producerPriv, recordingId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyArtist(producerId, CHALLENGE, recordingId, sig); err != nil {
		t.Fatal(err)
	}
	transferId, err = api.Transfer(recordingId, recordingId, 0, recordLabelPriv.Public(), 20)
	if err != nil {
		t.Fatal(err)
	}
	recordingRight, err := api.DefaultSendIndividualCreateTx(spec.NewRecordingRight([]string{performerId, recordLabelId}, recordingId, transferId))
	if err != nil {
		t.Fatal(err)
	}
	recordingRightId := GetId(recordingRight)
	WriteJSON(output, recordingRight)
	sig, err = ld.ProveRightHolder(CHALLENGE, performerPriv, performerId, recordingRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, performerId, recordingRightId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveRightHolder(CHALLENGE, recordLabelPriv, recordLabelId, recordingRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, recordLabelId, recordingRightId, sig); err != nil {
		t.Fatal(err)
	}
	if err = api.Login(recordLabelId, recordLabelPriv.String()); err != nil {
		t.Fatal(err)
	}
	release, err := api.DefaultSendIndividualCreateTx(spec.NewRelease("release_title", []string{recordingId}, recordLabelId, []string{recordingRightId}, "www.url_to_release.com"))
	if err != nil {
		t.Fatal(err)
	}
	releaseId := GetId(release)
	WriteJSON(output, release)
	sig, err = ld.ProveRecordLabel(CHALLENGE, recordLabelPriv, releaseId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRecordLabel(CHALLENGE, releaseId, sig); err != nil {
		t.Fatal(err)
	}
	masterLicense, err := api.DefaultSendIndividualCreateTx(spec.NewMasterLicense([]string{recordingId}, []string{radioId}, recordLabelId, []string{recordingRightId}, "2020-01-01", "2022-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	masterLicenseId := GetId(masterLicense)
	WriteJSON(output, masterLicense)
	sig, err = ld.ProveLicenseHolder(CHALLENGE, radioId, masterLicenseId, radioPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, radioId, masterLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	txs, err := bigchain.HttpGetFilter(func(txId string) (Data, error) {
		return ld.ValidateComposition(txId)
	}, composerPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	PrintJSON(txs)
}
