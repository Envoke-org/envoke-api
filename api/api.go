package api

import (
	"io"
	"net/http"

	// "github.com/dhowden/tag"
	"github.com/zbo14/envoke/bigchain"
	. "github.com/zbo14/envoke/common"
	"github.com/zbo14/envoke/crypto/crypto"
	"github.com/zbo14/envoke/crypto/ed25519"
	ld "github.com/zbo14/envoke/linked_data"
	"github.com/zbo14/envoke/spec"
)

type Api struct {
	id     string
	logger Logger
	priv   crypto.PrivateKey
	pub    crypto.PublicKey
}

func NewApi() *Api {
	return &Api{
		logger: NewLogger("api"),
	}
}

func (api *Api) AddRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/login_handler", api.LoginHandler)
	mux.HandleFunc("/register_handler", api.RegisterHandler)
	mux.HandleFunc("/compose_handler", api.ComposeHandler)
	mux.HandleFunc("/record_handler", api.RecordHandler)
	mux.HandleFunc("/composition_right_handler", api.CompositionRightHandler)
	mux.HandleFunc("/recording_right_handler", api.CompositionRightHandler)
	mux.HandleFunc("/publish_handler", api.PublishHandler)
	mux.HandleFunc("/release_handler", api.ReleaseHandler)
	mux.HandleFunc("/mechanical_license_handler", api.MechanicalLicenseHandler)
	mux.HandleFunc("/master_license_handler", api.MasterLicenseHandler)
	mux.HandleFunc("/prove_handler", api.ProveHandler)
	mux.HandleFunc("/verify_handler", api.VerifyHandler)
}

func (api *Api) LoginHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	form, err := MultipartForm(req)
	if err != nil {

		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	credentials, err := form.File["credentials"][0].Open()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	login := &struct {
		Id         string `json:"id"`
		PrivateKey string `json:"privateKey"`
	}{}
	if err = ReadJSON(credentials, login); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := api.Login(login.Id, login.PrivateKey); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (api *Api) RegisterHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	email := values.Get("email")
	ipi := values.Get("ipi")
	isni := values.Get("isni")
	memberIds := SplitStr(values.Get("memberIds"), ",")
	name := values.Get("name")
	password := values.Get("password")
	path := values.Get("path")
	pro := values.Get("pro")
	sameAs := values.Get("sameAs")
	_type := values.Get("type")
	party := spec.NewParty(email, ipi, isni, memberIds, name, pro, sameAs, _type)
	if _, err = api.Register(party, password, path); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte("Registration successful!"))
}

func (api *Api) CompositionRightHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	compositionId := values.Get("compositionId")
	outputIdx := MustAtoi(values.Get("outputIdx"))
	percentageShares := MustAtoi(values.Get("percentageShares"))
	rightHolderIds := []string{values.Get("rightHolderId")}
	tx, err := ld.QueryAndValidateSchema(rightHolderIds[0], "party")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rightHolderKey := bigchain.DefaultGetTxSender(tx)
	txId := values.Get("txId")
	transferId, err := api.Transfer(compositionId, txId, outputIdx, rightHolderKey, percentageShares)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	right, err := api.DefaultSendIndividualCreateTx(spec.NewCompositionRight(compositionId, rightHolderIds, transferId))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, right)
}

func (api *Api) RecordingRightHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	outputIdx := MustAtoi(values.Get("outputIdx"))
	percentageShares := MustAtoi(values.Get("percentageShares"))
	recordingId := values.Get("recordingId")
	rightHolderIds := []string{values.Get("rightHolderId")}
	tx, err := ld.QueryAndValidateSchema(rightHolderIds[0], "party")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rightHolderKey := bigchain.DefaultGetTxSender(tx)
	txId := values.Get("txId")
	transferId, err := api.Transfer(recordingId, txId, outputIdx, rightHolderKey, percentageShares)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	right, err := api.DefaultSendIndividualCreateTx(spec.NewCompositionRight(recordingId, rightHolderIds, transferId))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, right)
}

func (api *Api) Transfer(assetId, consumeId string, outputIdx int, owner crypto.PublicKey, percentageShares int) (string, error) {
	tx, err := bigchain.GetTx(consumeId)
	if err != nil {
		return "", err
	}
	if assetId != consumeId {
		if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
			return "", Error("Expected TRANSFER tx")
		}
		if assetId != bigchain.GetTxAssetId(tx) {
			return "", Error("consume tx does not have assetId")
		}
	}
	output := bigchain.GetTxOutput(tx, outputIdx)
	if !api.pub.Equals(bigchain.GetOutputPublicKeys(output)[0]) {
		return "", ErrorAppend(ErrInvalidKey, api.pub.String())
	}
	totalShares := bigchain.GetOutputAmount(output)
	keepShares := totalShares - percentageShares
	if keepShares == 0 {
		return api.SendIndividualTransferTx(percentageShares, assetId, consumeId, outputIdx, owner)
	}
	if keepShares > 0 {
		return api.SendDivisibleTransferTx([]int{keepShares, percentageShares}, assetId, consumeId, outputIdx, owner)
	}
	return "", Error("Cannot transfer that many shares")
}

func (api *Api) ComposeHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	composerIds := SplitStr(values.Get("composerIds"), ",")
	hfa := values.Get("hfa")
	iswc := values.Get("iswc")
	lang := values.Get("lang")
	name := values.Get("name")
	roles := SplitStr(values.Get("roles"), ",")
	sameAs := values.Get("sameAs")
	shares := SplitStr(values.Get("splits"), ",")
	percentageShares := make([]int, len(shares))
	for i, share := range shares {
		percentageShares[i] = MustAtoi(share)
	}
	uri := values.Get("uri")
	composition, err := api.Compose(
		spec.NewComposition(composerIds, hfa, iswc, lang, name, roles, sameAs, uri),
		percentageShares,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, composition)
}

func (api *Api) RecordHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	form, err := MultipartForm(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var recording Data
	artistIds := SplitStr(form.Value["artistId"][0], ",")
	compositionId := form.Value["compositionId"][0]
	duration := form.Value["duration"][0]
	file, err := form.File["recording"][0].Open()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	isrc := form.Value["isrc"][0]
	mechanicalLicenseIds := SplitStr(form.Value["mechanicalLicenseIds"][0], ",")
	roles := SplitStr(form.Value["roles"][0], ",")
	sameAs := form.Value["sameAs"][0]
	splits := SplitStr(form.Value["splits"][0], ",")
	percentageShares := make([]int, len(splits))
	for i, split := range splits {
		percentageShares[i] = MustAtoi(split)
	}
	uri := form.Value["uri"][0]
	recording, err = api.Record(
		file,
		percentageShares,
		spec.NewRecording(artistIds, compositionId, duration, isrc, mechanicalLicenseIds, roles, sameAs, uri),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, recording)
}

func (api *Api) PublishHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	compositionsId := SplitStr(values.Get("compositionId"), ",")
	name := values.Get("name")
	publisherId := values.Get("publisherId")
	rightIds := SplitStr(values.Get("rightIds"), ",")
	sameAs := values.Get("sameAs")
	publication, err := api.DefaultSendIndividualCreateTx(spec.NewPublication(compositionsId, name, publisherId, rightIds, sameAs))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, publication)
}

func (api *Api) ReleaseHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := values.Get("name")
	recordingIds := SplitStr(values.Get("recordingIds"), ",")
	recordLabelId := values.Get("recordLabelId")
	rightIds := SplitStr(values.Get("rightIds"), ",")
	sameAs := values.Get("sameAs")
	release, err := api.DefaultSendIndividualCreateTx(spec.NewRelease(name, recordingIds, recordLabelId, rightIds, sameAs))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, release)
}

func (api *Api) MechanicalLicenseHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	compositionIds := SplitStr(values.Get("compositionIds"), ",")
	licenseeId := values.Get("licenseeId")
	rightIds := SplitStr(values.Get("rightId"), ",")
	validFrom := values.Get("validFrom")
	validThrough := values.Get("validThrough")
	license, err := api.DefaultSendIndividualCreateTx(spec.NewMechanicalLicense(compositionIds, licenseeId, api.id, rightIds, validFrom, validThrough))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, license)
}

func (api *Api) MasterLicenseHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	licenseeId := values.Get("licenseeId")
	recordingIds := SplitStr(values.Get("recordingIds"), ",")
	rightIds := SplitStr(values.Get("rightId"), ",")
	validFrom := values.Get("validFrom")
	validThrough := values.Get("validThrough")
	license, err := api.DefaultSendIndividualCreateTx(spec.NewMasterLicense(licenseeId, api.id, recordingIds, rightIds, validFrom, validThrough))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, license)
}

func (api *Api) ProveHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var sig crypto.Signature
	challenge := values.Get("challenge")
	_type := values.Get("type")
	switch _type {
	case "composition":
		composerId := values.Get("composerId")
		compositionId := values.Get("compositionId")
		sig, err = ld.ProveComposer(challenge, composerId, compositionId, api.priv)
	case "composition_right":
		rightId := values.Get("rightId")
		rightHolderId := values.Get("rightHolderId")
		sig, err = ld.ProveCompositionRightHolder(challenge, rightId, api.priv, rightHolderId)
	case "master_license":
		licenseId := values.Get("licenseId")
		sig, err = ld.ProveMasterLicenseHolder(challenge, licenseId, api.priv)
	case "mechanical_license":
		licenseId := values.Get("licenseId")
		sig, err = ld.ProveMechanicalLicenseHolder(challenge, licenseId, api.priv)
	case "publication":
		publicationId := values.Get("publicationId")
		sig, err = ld.ProvePublisher(challenge, api.priv, publicationId)
	case "recording":
		artistId := values.Get("artistId")
		recordingId := values.Get("recordingId")
		sig, err = ld.ProveArtist(artistId, challenge, api.priv, recordingId)
	case "recording_right":
		rightId := values.Get("rightId")
		rightHolderId := values.Get("rightHolderId")
		sig, err = ld.ProveRecordingRightHolder(challenge, api.priv, rightId, rightHolderId)
	case "release":
		releaseId := values.Get("releaseId")
		sig, err = ld.ProveRecordLabel(challenge, api.priv, releaseId)
	default:
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, sig)
}

func (api *Api) VerifyHandler(w http.ResponseWriter, req *http.Request) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	values, err := UrlValues(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	challenge := values.Get("challenge")
	sig := new(ed25519.Signature)
	signature := values.Get("signature")
	if err := sig.FromString(signature); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_type := values.Get("type")
	switch _type {
	case "composition":
		composerId := values.Get("composerId")
		compositionId := values.Get("compositionId")
		err = ld.VerifyComposer(challenge, composerId, compositionId, sig)
	case "composition_right":
		rightId := values.Get("rightId")
		rightHolderId := values.Get("rightHolderId")
		err = ld.VerifyCompositionRightHolder(challenge, rightId, rightHolderId, sig)
	case "master_license":
		licenseId := values.Get("licenseId")
		err = ld.VerifyMasterLicenseHolder(challenge, licenseId, sig)
	case "mechanical_license":
		licenseId := values.Get("licenseId")
		err = ld.VerifyMechanicalLicenseHolder(challenge, licenseId, sig)
	case "publication":
		publicationId := values.Get("publicationId")
		err = ld.VerifyPublisher(challenge, publicationId, sig)
	case "recording":
		artistId := values.Get("artistId")
		recordingId := values.Get("recordingId")
		err = ld.VerifyArtist(artistId, challenge, recordingId, sig)
	case "recording_right":
		rightId := values.Get("rightId")
		rightHolderId := values.Get("rightHolderId")
		err = ld.VerifyRecordingRightHolder(challenge, rightId, rightHolderId, sig)
	case "release":
		releaseId := values.Get("releaseId")
		err = ld.VerifyRecordLabel(challenge, releaseId, sig)
	default:
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, "Verified signature!")
}

func (api *Api) LoggedIn() bool {
	switch {
	case api.id == "":
		api.logger.Warn("ID is not set")
	case api.priv == nil:
		api.logger.Warn("Private-key is not set")
	case api.pub == nil:
		api.logger.Warn("Public-key is not set")
	default:
		return true
	}
	api.logger.Error("LOGIN FAILED")
	return false
}

func (api *Api) DefaultSendIndividualCreateTx(data Data) (Data, error) {
	return api.SendIndividualCreateTx(1, data, api.pub)
}

func (api *Api) SendIndividualCreateTx(amount int, data Data, owner crypto.PublicKey) (Data, error) {
	_type := spec.GetType(data)
	tx := bigchain.IndividualCreateTx(amount, data, owner, api.pub)
	bigchain.FulfillTx(tx, api.priv)
	id, err := bigchain.PostTx(tx)
	if err != nil {
		return nil, err
	}
	return Data{
		_type: data,
		"id":  id,
	}, nil
}

func (api *Api) DefaultSendMultipleOwnersCreateTx(data Data, owners []crypto.PublicKey) (Data, error) {
	return api.SendMultipleOwnersCreateTx([]int{1}, data, owners)
}

func (api *Api) SendMultipleOwnersCreateTx(amounts []int, data Data, owners []crypto.PublicKey) (Data, error) {
	_type := spec.GetType(data)
	tx := bigchain.MultipleOwnersCreateTx(amounts, data, owners, api.pub)
	bigchain.FulfillTx(tx, api.priv)
	id, err := bigchain.PostTx(tx)
	if err != nil {
		return nil, err
	}
	return Data{
		_type: data,
		"id":  id,
	}, nil
}

func (api *Api) SendIndividualTransferTx(amount int, assetId, consumeId string, outputIdx int, owner crypto.PublicKey) (string, error) {
	tx := bigchain.IndividualTransferTx(amount, assetId, consumeId, outputIdx, owner, api.pub)
	bigchain.FulfillTx(tx, api.priv)
	id, err := bigchain.PostTx(tx)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (api *Api) SendDivisibleTransferTx(amounts []int, assetId, consumeId string, outputIdx int, owner crypto.PublicKey) (string, error) {
	tx := bigchain.DivisibleTransferTx(amounts, assetId, consumeId, outputIdx, []crypto.PublicKey{api.pub, owner}, api.pub)
	bigchain.FulfillTx(tx, api.priv)
	id, err := bigchain.PostTx(tx)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (api *Api) Login(id, privstr string) error {
	priv := new(ed25519.PrivateKey)
	if err := priv.FromString(privstr); err != nil {
		return err
	}
	tx, err := ld.QueryAndValidateSchema(id, "party")
	if err != nil {
		return err
	}
	party := bigchain.GetTxData(tx)
	pub := bigchain.DefaultGetTxSender(tx)
	if !pub.Equals(priv.Public()) {
		return ErrInvalidKey
	}
	api.logger.Info(Sprintf("SUCCESS %s is logged in", spec.GetName(party)))
	api.id = id
	api.priv, api.pub = priv, pub
	return nil
}

func (api *Api) Register(party Data, password, path string) (Data, error) {
	file, err := CreateFile(path + "/credentials.json")
	if err != nil {
		return nil, err
	}
	api.priv, api.pub = ed25519.GenerateKeypairFromPassword(password)
	party, err = api.DefaultSendIndividualCreateTx(party)
	if err != nil {
		return nil, err
	}
	credentials := Data{
		"id":         bigchain.GetId(party),
		"privateKey": api.priv.String(),
		"publicKey":  api.pub.String(),
	}
	api.priv, api.pub = nil, nil
	WriteJSON(file, credentials)
	return credentials, nil
}

func (api *Api) Compose(composition Data, percentageShares []int) (Data, error) {
	composers := spec.GetComposers(composition)
	n := len(composers)
	composerKeys := make([]crypto.PublicKey, n)
	for i, composer := range composers {
		tx, err := ld.QueryAndValidateSchema(spec.GetId(composer), "party")
		if err != nil {
			return nil, err
		}
		composerKeys[i] = bigchain.DefaultGetTxSender(tx)
	}
	if n == 1 {
		return api.SendIndividualCreateTx(100, composition, composerKeys[0])
	}
	return api.SendMultipleOwnersCreateTx(percentageShares, composition, composerKeys)
}

func (api *Api) Record(file io.Reader, percentageShares []int, recording Data) (Data, error) {
	// rs := MustReadSeeker(file)
	// meta, err := tag.ReadFrom(rs)
	// if err != nil {
	//	return nil, err
	// }
	// metadata := meta.Raw()
	artists := spec.GetArtists(recording)
	n := len(artists)
	artistKeys := make([]crypto.PublicKey, n)
	for i, artist := range artists {
		tx, err := ld.QueryAndValidateSchema(spec.GetId(artist), "party")
		if err != nil {
			return nil, err
		}
		artistKeys[i] = bigchain.DefaultGetTxSender(tx)
	}
	if n == 1 {
		return api.SendIndividualCreateTx(100, recording, artistKeys[0])
	}
	return api.SendMultipleOwnersCreateTx(percentageShares, recording, artistKeys)
}
