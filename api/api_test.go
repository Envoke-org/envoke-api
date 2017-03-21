package api

import (
	"testing"

	. "github.com/zbo14/envoke/common"
	conds "github.com/zbo14/envoke/crypto/conditions"
	"github.com/zbo14/envoke/crypto/crypto"
	"github.com/zbo14/envoke/crypto/ed25519"
	"github.com/zbo14/envoke/spec"
)

const DIR = "/Users/zach/Desktop/envoke/"

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
		"itsasecret",
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
	if err := api.Login(composerId, composerPriv.String()); err != nil {
		t.Fatal(err)
	}
	composition, err := api.Compose(spec.NewComposition([]string{composerId}, "B3107S", "T-034.524.680-1", "EN", "composition_title", nil, "www.url_to_composition.com", ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	compositionId := GetId(composition)
	WriteJSON(output, composition)
	transferId, err := api.Transfer(compositionId, compositionId, 0, publisherPriv.Public(), 20)
	if err != nil {
		t.Fatal(err)
	}
	publisherRight, err := api.DefaultSendIndividualCreateTx(spec.NewCompositionRight(compositionId, []string{composerId, publisherId}, transferId))
	if err != nil {
		t.Fatal(err)
	}
	publisherRightId := GetId(publisherRight)
	WriteJSON(output, publisherRight)
	if err = api.Login(publisherId, publisherPriv.String()); err != nil {
		t.Fatal(err)
	}
	publication, err := api.DefaultSendIndividualCreateTx(spec.NewPublication([]string{compositionId}, "publication_title", publisherId, []string{publisherRightId}, "www.url_to_publication.com"))
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, publication)
	performerLicense, err := api.DefaultSendIndividualCreateTx(spec.NewMechanicalLicense([]string{compositionId}, performerId, publisherId, []string{publisherRightId}, "2020-01-01", "2024-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	performerLicenseId := GetId(performerLicense)
	WriteJSON(output, performerLicense)
	producerLicense, err := api.DefaultSendIndividualCreateTx(spec.NewMechanicalLicense([]string{compositionId}, producerId, publisherId, []string{publisherRightId}, "2020-01-01", "2024-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	producerLicenseId := GetId(producerLicense)
	WriteJSON(output, producerLicense)
	file, err := OpenFile(Getenv("PATH_TO_AUDIO_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	if err = api.Login(performerId, performerPriv.String()); err != nil {
		t.Fatal(err)
	}
	signRecording := spec.NewRecording([]string{performerId, producerId}, compositionId, "PT2M43S", "US-S1Z-99-00001", []string{performerLicenseId, producerLicenseId}, []string{"performer", "producer"}, "www.url_to_recording.com", "")
	checksum := Checksum256(MustMarshalJSON(signRecording))
	ful := conds.DefaultFulfillmentThresholdFromPrivKeys(checksum, performerPriv, producerPriv)
	signRecording.Set("uri", ful.String())
	recording, err := api.Record(file, []int{80, 20}, signRecording)
	if err != nil {
		t.Fatal(err)
	}
	recordingId := GetId(recording)
	WriteJSON(output, recording)
	transferId, err = api.Transfer(recordingId, recordingId, 0, recordLabelPriv.Public(), 20)
	if err != nil {
		t.Fatal(err)
	}
	recordLabelRight, err := api.DefaultSendIndividualCreateTx(spec.NewRecordingRight(recordingId, []string{performerId, recordLabelId}, transferId))
	if err != nil {
		t.Fatal(err)
	}
	recordLabelRightId := GetId(recordLabelRight)
	WriteJSON(output, recordLabelRight)
	if err = api.Login(recordLabelId, recordLabelPriv.String()); err != nil {
		t.Fatal(err)
	}
	release, err := api.DefaultSendIndividualCreateTx(spec.NewRelease("release_title", []string{recordingId}, recordLabelId, []string{recordLabelRightId}, "www.url_to_release.com"))
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, release)
	masterLicense, err := api.DefaultSendIndividualCreateTx(spec.NewMasterLicense(radioId, recordLabelId, []string{recordingId}, []string{recordLabelRightId}, "2020-01-01", "2022-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, masterLicense)
}
