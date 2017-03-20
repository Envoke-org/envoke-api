package api

import (
	"testing"

	. "github.com/zbo14/envoke/common"
	conds "github.com/zbo14/envoke/crypto/conditions"
	"github.com/zbo14/envoke/crypto/crypto"
	"github.com/zbo14/envoke/crypto/ed25519"
	"github.com/zbo14/envoke/spec"
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
	composer, err := api.Register("composer@email.com", "", "", nil, "composer", "itsasecret", "", "www.composer.com", "Person")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, composer)
	composerId := GetId(composer)
	composerPriv := GetPrivateKey(composer)
	recordLabel, err := api.Register("record_label@email.com", "", "", nil, "record_label", "shhhh", "", "www.record_label.com", "Organization")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, recordLabel)
	recordLabelId := GetId(recordLabel)
	recordLabelPriv := GetPrivateKey(recordLabel)
	performer, err := api.Register("performer@email.com", "123456789", "", nil, "performer", "makeitup", "ASCAP", "www.performer.com", "MusicGroup")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, performer)
	performerId := GetId(performer)
	performerPriv := GetPrivateKey(performer)
	producer, err := api.Register("producer@email.com", "", "", nil, "producer", "1234", "", "www.soundcloud_page.com", "Person")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, producer)
	producerId := GetId(producer)
	producerPriv := GetPrivateKey(producer)
	if err = api.Login(performerId, performerPriv.String()); err != nil {
		t.Fatal(err)
	}
	collab, err := api.Collaborate([]string{performerId, producerId}, "collab", []string{"performer", "producer"}, []int{60, 40})
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, collab)
	collabId := GetId(collab)
	publisher, err := api.Register("publisher@email.com", "", "", nil, "publisher", "didyousaysomething?", "", "www.soundcloud_page.com", "MusicGroup")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, publisher)
	publisherId := GetId(publisher)
	publisherPriv := GetPrivateKey(publisher)
	radio, err := api.Register("radio@email.com", "", "", nil, "radio", "waves", "", "www.radio_station.com", "Organization")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, radio)
	radioId := GetId(radio)
	if err = api.Login(composerId, composerPriv.String()); err != nil {
		t.Fatal(err)
	}
	composition, err := api.SendTxComposition(spec.NewComposition(false, composerId, "B3107S", "T-034.524.680-1", "EN", publisherId, "www.url_to_composition.com", "untitled", ""))
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, composition)
	compositionId := GetId(composition)
	composerRight, err := api.SendTxRight(20, spec.NewCompositionRight(composerId, composerId, []string{"GB", "US"}, "", "2020-01-01", "2096-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, composerRight)
	composerRightId := GetId(composerRight)
	publisherRight, err := api.SendTxRight(80, spec.NewCompositionRight(publisherId, composerId, []string{"GB", "US"}, "", "2020-01-01", "2096-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, publisherRight)
	publisherRightId := GetId(publisherRight)
	publication, err := api.SendTxPublication(spec.NewPublication([]string{compositionId}, []string{composerRightId, publisherRightId}, publisherId, "www.url_to_publication.com", "publication_title"))
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, publication)
	publicationId := GetId(publication)
	if err = api.Login(publisherId, publisherPriv.String()); err != nil {
		t.Fatal(err)
	}
	mechanicalLicense, err := api.SendTxLicense(spec.NewMechanicalLicense(nil, publisherRightId, "", publicationId, collabId, []string{"US"}, nil, "2020-01-01", "2024-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, mechanicalLicense)
	mechanicalLicenseId := GetId(mechanicalLicense)
	file, err := OpenFile(Getenv("PATH_TO_AUDIO_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	if err = api.Login(performerId, performerPriv.String()); err != nil {
		t.Fatal(err)
	}
	signRecording := spec.NewRecording(collabId, true, compositionId, "", "PT2M43S", "US-S1Z-99-00001", mechanicalLicenseId, "", recordLabelId, "www.url_to_recording.com", "")
	checksum := Checksum256(MustMarshalJSON(signRecording))
	fulfillment := conds.DefaultFulfillmentThresholdFromPrivKeys(checksum, performerPriv, producerPriv)
	recording, err := api.Record(collabId, true, compositionId, "", "PT2M43S", file, "US-S1Z-99-00001", mechanicalLicenseId, "", recordLabelId, "www.url_to_recording.com", fulfillment.String())
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, recording)
	recordingId := GetId(recording)
	signRecordingRight := spec.NewRecordingRight(collabId, collabId, []string{"GB", "US"}, "", "2020-01-01", "2080-01-01")
	checksum = Checksum256(MustMarshalJSON(signRecordingRight))
	fulfillment = conds.DefaultFulfillmentThresholdFromPrivKeys(checksum, performerPriv, producerPriv)
	collabRight, err := api.RecordingRight(collabId, 30, collabId, []string{"GB", "US"}, fulfillment.String(), "2020-01-01", "2080-01-01")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, collabRight)
	collabRightId := GetId(collabRight)
	signRecordingRight = spec.NewRecordingRight(recordLabelId, collabId, []string{"GB", "US"}, "", "2020-01-01", "2080-01-01")
	checksum = Checksum256(MustMarshalJSON(signRecordingRight))
	fulfillment = conds.DefaultFulfillmentThresholdFromPrivKeys(checksum, performerPriv, producerPriv)
	recordLabelRight, err := api.RecordingRight(recordLabelId, 70, collabId, []string{"GB", "US"}, fulfillment.String(), "2020-01-01", "2080-01-01")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, recordLabelRight)
	recordLabelRightId := GetId(recordLabelRight)
	release, err := api.Release([]string{recordingId}, []string{collabRightId, recordLabelRightId}, recordLabelId, "www.url_to_release.com", "release_title")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, release)
	releaseId := GetId(release)
	if err = api.Login(recordLabelId, recordLabelPriv.String()); err != nil {
		t.Fatal(err)
	}
	masterLicense, err := api.MasterLicense(radioId, nil, recordLabelRightId, "", releaseId, []string{"US"}, nil, "2020-01-01", "2022-01-01")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, masterLicense)
	if err = api.Login(composerId, composerPriv.String()); err != nil {
		t.Fatal(err)
	}
	SleepSeconds(2)
	compositionRightTransfer, err := api.TransferCompositionRight(composerRightId, "", publicationId, publisherId, 10)
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, compositionRightTransfer)
	compositionRightTransferId := GetId(compositionRightTransfer)
	if err = api.Login(publisherId, publisherPriv.String()); err != nil {
		t.Fatal(err)
	}
	SleepSeconds(2)
	compositionRightTransfer, err = api.TransferCompositionRight(composerRightId, compositionRightTransferId, publicationId, composerId, 5)
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, compositionRightTransfer)
	compositionRightTransferId = GetId(compositionRightTransfer)
	if err = api.Login(recordLabelId, recordLabelPriv.String()); err != nil {
		t.Fatal(err)
	}
	SleepSeconds(2)
	recordingRightTransfer, err := api.TransferRecordingRight(performerId, 10, recordLabelRightId, "", releaseId)
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, recordingRightTransfer)
	recordingRightTransferId := GetId(recordingRightTransfer)
	if err = api.Login(performerId, performerPriv.String()); err != nil {
		t.Fatal(err)
	}
	SleepSeconds(2)
	recordingRightTransfer, err = api.TransferRecordingRight(recordLabelId, 5, recordLabelRightId, recordingRightTransferId, releaseId)
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, recordingRightTransfer)
	if err = api.Login(composerId, composerPriv.String()); err != nil {
		t.Fatal(err)
	}
	mechanicalLicenseFromTransfer, err := api.MechanicalLicense(nil, "", compositionRightTransferId, publicationId, radioId, []string{"US"}, nil, "2020-01-01", "2030-01-01")
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, mechanicalLicenseFromTransfer)
}
