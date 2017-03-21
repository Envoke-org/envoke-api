package api

import (
	"testing"

	. "github.com/zbo14/envoke/common"
	cc "github.com/zbo14/envoke/crypto/conditions"
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
	radioPriv := GetPrivateKey(radio)
	WriteJSON(output, radio)
	if err := api.Login(composerId, composerPriv.String()); err != nil {
		t.Fatal(err)
	}
	composition, err := api.Compose(spec.NewComposition([]string{composerId}, "B3107S", "T-034.524.680-1", "EN", "composition_title", nil, "www.url_to_composition.com", ""), nil)
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
	compositionRight, err := api.DefaultSendIndividualCreateTx(spec.NewCompositionRight(compositionId, []string{composerId, publisherId}, transferId))
	if err != nil {
		t.Fatal(err)
	}
	compositionRightId := GetId(compositionRight)
	WriteJSON(output, compositionRight)
	sig, err = ld.ProveCompositionRightHolder(CHALLENGE, compositionRightId, composerPriv, composerId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyCompositionRightHolder(CHALLENGE, compositionRightId, composerId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveCompositionRightHolder(CHALLENGE, compositionRightId, publisherPriv, publisherId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyCompositionRightHolder(CHALLENGE, compositionRightId, publisherId, sig); err != nil {
		t.Fatal(err)
	}
	if err = api.Login(publisherId, publisherPriv.String()); err != nil {
		t.Fatal(err)
	}
	publication, err := api.DefaultSendIndividualCreateTx(spec.NewPublication([]string{compositionId}, "publication_title", publisherId, []string{compositionRightId}, "www.url_to_publication.com"))
	if err != nil {
		t.Fatal(err)
	}
	publicationId := GetId(publication)
	WriteJSON(output, publication)
	sig, err = ld.ProvePublisher(CHALLENGE, publisherPriv, publicationId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyPublisher(CHALLENGE, publicationId, sig); err != nil {
		t.Fatal(err)
	}
	performerLicense, err := api.DefaultSendIndividualCreateTx(spec.NewMechanicalLicense([]string{compositionId}, performerId, publisherId, []string{compositionRightId}, "2020-01-01", "2024-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	performerLicenseId := GetId(performerLicense)
	WriteJSON(output, performerLicense)
	sig, err = ld.ProveMechanicalLicenseHolder(CHALLENGE, performerLicenseId, performerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyMechanicalLicenseHolder(CHALLENGE, performerLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	producerLicense, err := api.DefaultSendIndividualCreateTx(spec.NewMechanicalLicense([]string{compositionId}, producerId, publisherId, []string{compositionRightId}, "2020-01-01", "2024-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	producerLicenseId := GetId(producerLicense)
	WriteJSON(output, producerLicense)
	sig, err = ld.ProveMechanicalLicenseHolder(CHALLENGE, producerLicenseId, producerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyMechanicalLicenseHolder(CHALLENGE, producerLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	file, err := OpenFile(Getenv("PATH_TO_AUDIO_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	if err = api.Login(performerId, performerPriv.String()); err != nil {
		t.Fatal(err)
	}
	signRecording := spec.NewRecording([]string{performerId, producerId}, compositionId, "PT2M43S", "US-S1Z-99-00001", []string{performerLicenseId, producerLicenseId}, []string{"performer", "producer"}, "www.url_to_recording.com", "")
	checksum := Checksum256(MustMarshalJSON(signRecording))
	ful := cc.DefaultFulfillmentThresholdFromPrivKeys(checksum, performerPriv, producerPriv)
	signRecording.Set("uri", ful.String())
	recording, err := api.Record(file, []int{80, 20}, signRecording)
	if err != nil {
		t.Fatal(err)
	}
	recordingId := GetId(recording)
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
	recordingRight, err := api.DefaultSendIndividualCreateTx(spec.NewRecordingRight(recordingId, []string{performerId, recordLabelId}, transferId))
	if err != nil {
		t.Fatal(err)
	}
	recordingRightId := GetId(recordingRight)
	WriteJSON(output, recordingRight)
	sig, err = ld.ProveRecordingRightHolder(CHALLENGE, performerPriv, recordingRightId, performerId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRecordingRightHolder(CHALLENGE, recordingRightId, performerId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveRecordingRightHolder(CHALLENGE, recordLabelPriv, recordingRightId, recordLabelId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRecordingRightHolder(CHALLENGE, recordingRightId, recordLabelId, sig); err != nil {
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
	masterLicense, err := api.DefaultSendIndividualCreateTx(spec.NewMasterLicense(radioId, recordLabelId, []string{recordingId}, []string{recordingRightId}, "2020-01-01", "2022-01-01"))
	if err != nil {
		t.Fatal(err)
	}
	masterLicenseId := GetId(masterLicense)
	WriteJSON(output, masterLicense)
	sig, err = ld.ProveMasterLicenseHolder(CHALLENGE, masterLicenseId, radioPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyMasterLicenseHolder(CHALLENGE, masterLicenseId, sig); err != nil {
		t.Fatal(err)
	}
}
