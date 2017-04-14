package api

import (
	"testing"
	"time"

	"github.com/Envoke-org/envoke-api/bigchain"
	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
	ld "github.com/Envoke-org/envoke-api/linked_data"
	"github.com/Envoke-org/envoke-api/spec"
)

var CHALLENGE = "abc"

func GetPrivateKey(data Data) crypto.PrivateKey {
	privkey := new(ed25519.PrivateKey)
	privkey.FromString(data.GetStr("privateKey"))
	return privkey
}

func GetUserId(data Data) string {
	return data.GetStr("userId")
}

func TestApi(t *testing.T) {

	composer, _ := spec.NewUser("composer@email.com", "", nil, "composer", "www.composer.com", "Person")
	performer, _ := spec.NewUser("performer@email.com", "", nil, "performer", "www.performer.com", "MusicGroup")
	producer, _ := spec.NewUser("producer@email.com", "", nil, "producer", "www.soundcloud_page.com", "Person")
	publisher, _ := spec.NewUser("publisher@email.com", "", nil, "publisher", "www.publisher.com", "Organization")
	radio, _ := spec.NewUser("radio@email.com", "", nil, "radio", "www.radio_station.com", "Organization")
	recordLabel, _ := spec.NewUser("record_label@email.com", "", nil, "record_label", "www.record_label.com", "Organization")

	api := NewApi()
	output := MustOpenWriteFile("output.json")

	credentials, err := api.Register("itisasecret", composer)
	if err != nil {
		t.Fatal(err)
	}
	composerId := GetUserId(credentials)
	composerPrivkey := GetPrivateKey(credentials)
	WriteJSON(output, credentials)
	credentials, err = api.Register("makeitup", performer)
	if err != nil {
		t.Fatal(err)
	}
	performerId := GetUserId(credentials)
	performerPrivkey := GetPrivateKey(credentials)
	WriteJSON(output, credentials)
	credentials, err = api.Register("1234", producer)
	if err != nil {
		t.Fatal(err)
	}
	producerId := GetUserId(credentials)
	producerPrivkey := GetPrivateKey(credentials)
	WriteJSON(output, credentials)
	credentials, err = api.Register("didyousaysomething?", publisher)
	if err != nil {
		t.Fatal(err)
	}
	publisherId := GetUserId(credentials)
	publisherPrivkey := GetPrivateKey(credentials)
	WriteJSON(output, credentials)
	credentials, err = api.Register("waves", radio)
	if err != nil {
		t.Fatal(err)
	}
	radioId := GetUserId(credentials)
	radioPrivkey := GetPrivateKey(credentials)
	WriteJSON(output, credentials)
	credentials, err = api.Register("shhhh", recordLabel)
	if err != nil {
		t.Fatal(err)
	}
	recordLabelId := GetUserId(credentials)
	recordLabelPrivkey := GetPrivateKey(credentials)
	WriteJSON(output, credentials)
	if err := api.Login(composerPrivkey.String(), composerId); err != nil {
		t.Fatal(err)
	}
	composition, err := spec.NewComposition([]string{composerId}, "T-034.524.680-1", "EN", "composition_title", []string{publisherId}, "www.composition_url.com")
	if err != nil {
		t.Fatal(err)
	}
	composerSignature, err := api.SignComposition(composition, []int{20, 80})
	if err != nil {
		t.Fatal(err)
	}
	if err = api.Login(publisherPrivkey.String(), publisherId); err != nil {
		t.Fatal(err)
	}
	publisherSignature, err := api.SignComposition(composition, []int{20, 80})
	if err != nil {
		t.Fatal(err)
	}
	compositionId, err := api.Publish(composition, []string{composerSignature, publisherSignature}, []int{20, 80})
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"compositionId": compositionId})
	if err := api.Login(composerPrivkey.String(), composerId); err != nil {
		t.Fatal(err)
	}
	sig, err := ld.ProveComposer(CHALLENGE, composerId, compositionId, composerPrivkey)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyComposer(CHALLENGE, composerId, compositionId, sig); err != nil {
		t.Fatal(err)
	}
	SleepSeconds(2)
	compositionRightId, err := api.Right(compositionId, []string{recordLabelId}, []int{10})
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"compositionRightId": compositionRightId})
	SleepSeconds(2)
	sig, err = ld.ProveRightHolder(CHALLENGE, composerPrivkey, composerId, compositionRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, composerId, compositionRightId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveRightHolder(CHALLENGE, recordLabelPrivkey, recordLabelId, compositionRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, recordLabelId, compositionRightId, sig); err != nil {
		t.Fatal(err)
	}
	if err = api.Login(publisherPrivkey.String(), publisherId); err != nil {
		t.Fatal(err)
	}
	mechanicalLicenseId, err := api.License([]string{compositionId}, []time.Time{NilTime, Date(1, 1, 2024, nil)}, []string{performerId, producerId})
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"mechanicalLicenseId": mechanicalLicenseId})
	sig, err = ld.ProveLicenseHolder(CHALLENGE, performerId, mechanicalLicenseId, performerPrivkey)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, performerId, mechanicalLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveLicenseHolder(CHALLENGE, producerId, mechanicalLicenseId, producerPrivkey)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, producerId, mechanicalLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	if err = api.Login(performerPrivkey.String(), performerId); err != nil {
		t.Fatal(err)
	}
	recording, err := spec.NewRecording([]string{performerId, producerId}, compositionId, "PT2M43S", "US-S1Z-99-00001", []string{mechanicalLicenseId, mechanicalLicenseId, ""}, []string{recordLabelId}, "www.recording_url.com")
	if err != nil {
		t.Fatal(err)
	}
	perfomerSignature, err := api.SignRecording(recording, []int{30, 10, 60})
	if err != nil {
		t.Fatal(err)
	}
	if err = api.Login(producerPrivkey.String(), producerId); err != nil {
		t.Fatal(err)
	}
	producerSignature, err := api.SignRecording(recording, []int{30, 10, 60})
	if err != nil {
		t.Fatal(err)
	}
	if err = api.Login(recordLabelPrivkey.String(), recordLabelId); err != nil {
		t.Fatal(err)
	}
	recordLabelSignature, err := api.SignRecording(recording, []int{30, 10, 60})
	if err != nil {
		t.Fatal(err)
	}
	recordingId, err := api.Release(recording, []string{perfomerSignature, producerSignature, recordLabelSignature}, []int{30, 10, 60})
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"recordingId": recordingId})
	SleepSeconds(2)
	sig, err = ld.ProveArtist(performerId, CHALLENGE, performerPrivkey, recordingId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyArtist(performerId, CHALLENGE, recordingId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveArtist(producerId, CHALLENGE, producerPrivkey, recordingId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyArtist(producerId, CHALLENGE, recordingId, sig); err != nil {
		t.Fatal(err)
	}
	if err = api.Login(recordLabelPrivkey.String(), recordLabelId); err != nil {
		t.Fatal(err)
	}
	masterLicenseId, err := api.License([]string{recordingId}, []time.Time{Date(1, 1, 2024, nil)}, []string{radioId})
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"masterLicenseId": masterLicenseId})
	recordingRightId, err := api.Right(recordingId, []string{performerId, producerId}, []int{5, 5})
	if err != nil {
		t.Fatal(err)
	}
	WriteJSON(output, Data{"recordingRightId": recordingRightId})
	SleepSeconds(2)
	sig, err = ld.ProveRightHolder(CHALLENGE, producerPrivkey, producerId, recordingRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, producerId, recordingRightId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveRightHolder(CHALLENGE, recordLabelPrivkey, recordLabelId, recordingRightId)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyRightHolder(CHALLENGE, recordLabelId, recordingRightId, sig); err != nil {
		t.Fatal(err)
	}
	sig, err = ld.ProveLicenseHolder(CHALLENGE, radioId, masterLicenseId, radioPrivkey)
	if err != nil {
		t.Fatal(err)
	}
	if err = ld.VerifyLicenseHolder(CHALLENGE, radioId, masterLicenseId, sig); err != nil {
		t.Fatal(err)
	}
	txs, err := bigchain.HttpGetFilter(func(txId string) (Data, error) {
		return ld.ValidateCompositionId(txId)
	}, composerPrivkey.Public(), false)
	if err != nil {
		t.Fatal(err)
	}
	PrintJSON(txs)
}
