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
	mux.HandleFunc("/compose_handler", api.ComposeHandler)
	mux.HandleFunc("/license_handler", api.LicenseHandler)
	mux.HandleFunc("/login_handler", api.LoginHandler)
	mux.HandleFunc("/prove_handler", api.ProveHandler)
	mux.HandleFunc("/record_handler", api.RecordHandler)
	mux.HandleFunc("/register_handler", api.RegisterHandler)
	mux.HandleFunc("/release_handler", api.ReleaseHandler)
	mux.HandleFunc("/right_handler", api.RightHandler)
	mux.HandleFunc("/search_handler", api.SearchHandler)
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

func (api *Api) RightHandler(w http.ResponseWriter, req *http.Request) {
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
	rightHolderIds := []string{values.Get("rightHolderId")}
	rightToId := values.Get("rightToId")
	tx, err := ld.QueryAndValidateSchema(rightHolderIds[0], "party")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rightHolderKey := bigchain.DefaultGetTxSender(tx)
	txId := values.Get("txId")
	transferId, err := api.Transfer(rightToId, txId, outputIdx, rightHolderKey, percentageShares)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var right Data
	switch _type := values.Get("type"); _type {
	case "composition_right":
		right, err = api.DefaultSendIndividualCreateTx(spec.NewCompositionRight(rightHolderIds, rightToId, transferId))
	case "recording_right":
		right, err = api.DefaultSendIndividualCreateTx(spec.NewRecordingRight(rightHolderIds, rightToId, transferId))
	default:
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, right)
}

func (api *Api) Transfer(assetId, consumeId string, outputIdx int, owner crypto.PublicKey, percentageShares int) (string, error) {
	tx, err := bigchain.HttpGetTx(consumeId)
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
	publisherId := values.Get("publisherId")
	roles := SplitStr(values.Get("roles"), ",")
	sameAs := values.Get("sameAs")
	shares := SplitStr(values.Get("splits"), ",")
	var percentageShares []int = nil
	if len(shares) > 1 {
		percentageShares = make([]int, len(shares))
		for i, share := range shares {
			percentageShares[i] = MustAtoi(share)
		}
	}
	uri := values.Get("uri")
	composition, err := api.Compose(
		spec.NewComposition(composerIds, hfa, iswc, lang, name, publisherId, roles, sameAs, uri),
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
	var percentageShares []int = nil
	if len(splits) > 1 {
		percentageShares = make([]int, len(splits))
		for i, split := range splits {
			percentageShares[i] = MustAtoi(split)
		}
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

func (api *Api) LicenseHandler(w http.ResponseWriter, req *http.Request) {
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
	licenseForIds := SplitStr(values.Get("licenseForIds"), ",")
	licenseHolderIds := SplitStr(values.Get("licenseHolderIds"), ",")
	rightIds := SplitStr(values.Get("rightId"), ",")
	_type := values.Get("type")
	validFrom := values.Get("validFrom")
	validThrough := values.Get("validThrough")
	var license Data
	switch _type {
	case "master_license":
		license, err = api.DefaultSendIndividualCreateTx(spec.NewMasterLicense(licenseForIds, licenseHolderIds, api.id, rightIds, validFrom, validThrough))
	case "mechanical_license":
		license, err = api.DefaultSendIndividualCreateTx(spec.NewMechanicalLicense(licenseForIds, licenseHolderIds, api.id, rightIds, validFrom, validThrough))
	default:
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, license)
}

func CompositionFilter(compositionId, name string) (Data, error) {
	composition, err := ld.ValidateComposition(compositionId)
	if err != nil {
		return nil, err
	}
	if !EmptyStr(name) && !MatchStr(name, spec.GetName(composition)) {
		return nil, Error("name does not match")
	}
	return composition, nil
}

func RecordingFilter(recordingId, name string) (Data, error) {
	recording, err := ld.ValidateRecording(recordingId)
	if err != nil {
		return nil, err
	}
	if !EmptyStr(name) {
		compositionId := spec.GetRecordingOfId(recording)
		if _, err = CompositionFilter(compositionId, name); err != nil {
			return nil, err
		}
	}
	return recording, nil
}

func (api *Api) SearchHandler(w http.ResponseWriter, req *http.Request) {
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
	var models []Data
	name := values.Get("name")
	partyId := values.Get("partyId")
	tx, err := ld.QueryAndValidateSchema(partyId, "party")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pub := bigchain.DefaultGetTxSender(tx)
	_type := values.Get("type")
	switch _type {
	case "composition":
		models, err = bigchain.HttpGetFilter(func(txId string) (Data, error) {
			return CompositionFilter(txId, name)
		}, pub)
	case "license":
		models, err = bigchain.HttpGetFilter(func(txId string) (Data, error) {
			return ld.ValidateLicense(txId)
		}, pub)
	case "recording":
		models, err = bigchain.HttpGetFilter(func(txId string) (Data, error) {
			return RecordingFilter(txId, name)
		}, pub)
	case "release":
		models, err = bigchain.HttpGetFilter(func(txId string) (Data, error) {
			return ld.ValidateRelease(txId)
		}, pub)
	case "right":
		models, err = bigchain.HttpGetFilter(func(txId string) (Data, error) {
			return ld.ValidateRight(txId)
		}, pub)
	default:
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, models)
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
	modelId := values.Get("modelId")
	partyId := values.Get("partyId")
	_type := values.Get("type")
	switch _type {
	case "composition":
		sig, err = ld.ProveComposer(challenge, partyId, modelId, api.priv)
	case "license":
		sig, err = ld.ProveLicenseHolder(challenge, partyId, modelId, api.priv)
	case "recording":
		sig, err = ld.ProveArtist(partyId, challenge, api.priv, modelId)
	case "release":
		sig, err = ld.ProveRecordLabel(challenge, api.priv, modelId)
	case "right":
		sig, err = ld.ProveRightHolder(challenge, api.priv, partyId, modelId)
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
	modelId := values.Get("modelId")
	partyId := values.Get("partyId")
	sig := new(ed25519.Signature)
	signature := values.Get("signature")
	if err := sig.FromString(signature); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_type := values.Get("type")
	switch _type {
	case "composition":
		err = ld.VerifyComposer(challenge, partyId, modelId, sig)
	case "license":
		err = ld.VerifyLicenseHolder(challenge, partyId, modelId, sig)
	case "recording":
		err = ld.VerifyArtist(partyId, challenge, modelId, sig)
	case "release":
		err = ld.VerifyRecordLabel(challenge, modelId, sig)
	case "right":
		err = ld.VerifyRightHolder(challenge, modelId, partyId, sig)
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
	id, err := bigchain.HttpPostTx(tx)
	if err != nil {
		return nil, err
	}
	api.logger.Info("SUCCESS sent CREATE tx with " + _type)
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
	id, err := bigchain.HttpPostTx(tx)
	if err != nil {
		return nil, err
	}
	api.logger.Info("SUCCESS sent CREATE tx with " + _type)
	return Data{
		_type: data,
		"id":  id,
	}, nil
}

func (api *Api) SendIndividualTransferTx(amount int, assetId, consumeId string, outputIdx int, owner crypto.PublicKey) (string, error) {
	tx := bigchain.IndividualTransferTx(amount, assetId, consumeId, outputIdx, owner, api.pub)
	bigchain.FulfillTx(tx, api.priv)
	id, err := bigchain.HttpPostTx(tx)
	if err != nil {
		return "", err
	}
	api.logger.Info("SUCCESS sent TRANSFER tx")
	return id, nil
}

func (api *Api) SendDivisibleTransferTx(amounts []int, assetId, consumeId string, outputIdx int, owner crypto.PublicKey) (string, error) {
	tx := bigchain.DivisibleTransferTx(amounts, assetId, consumeId, outputIdx, []crypto.PublicKey{api.pub, owner}, api.pub)
	bigchain.FulfillTx(tx, api.priv)
	id, err := bigchain.HttpPostTx(tx)
	if err != nil {
		return "", err
	}
	api.logger.Info("SUCCESS sent TRANSFER tx")
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
