package api

import (
	"io"
	"net/http"

	// "github.com/dhowden/tag"
	"github.com/zbo14/envoke/bigchain"
	. "github.com/zbo14/envoke/common"
	cc "github.com/zbo14/envoke/crypto/conditions"
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
	mux.HandleFunc("/composition", api.CompositionHandler)
	mux.HandleFunc("/license", api.LicenseHandler)
	mux.HandleFunc("/login", api.LoginHandler)
	mux.HandleFunc("/prove", api.ProveHandler)
	mux.HandleFunc("/recording", api.RecordingHandler)
	mux.HandleFunc("/register", api.RegisterHandler)
	mux.HandleFunc("/right", api.RightHandler)
	mux.HandleFunc("/search", api.SearchHandler)
	mux.HandleFunc("/verify", api.VerifyHandler)

	// mux.HandleFunc("/release", api.ReleaseHandler)
	// mux.HandleFunc("/sign", api.SignHandler)
	// mux.HandleFunc("/threshold", api.ThresholdHandler)
}

func (api *Api) LoginHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	if err := req.ParseMultipartForm(1000); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	credentials, err := req.MultipartForm.File["credentials"][0].Open()
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
	email := req.PostFormValue("email")
	ipiNumer := req.PostFormValue("ipiNumber")
	isniNumber := req.PostFormValue("isniNumber")
	memberIds := req.PostForm["memberIds"]
	name := req.PostFormValue("name")
	password := req.PostFormValue("password")
	path := req.PostFormValue("path")
	pro := req.PostFormValue("pro")
	sameAs := req.PostFormValue("sameAs")
	_type := req.PostFormValue("type")
	user := spec.NewUser(email, ipiNumer, isniNumber, memberIds, name, pro, sameAs, _type)
	if _, err := api.Register(user, password, path); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte("Registration successful!"))
}

func (api *Api) RightHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	percentShares, err := Atoi(req.PostFormValue("percentShares"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rightHolderId := req.PostFormValue("rightHolderId")
	rightToId := req.PostFormValue("rightToId")
	tx, err := ld.QueryAndValidateSchema(rightHolderId, "user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rightHolderKey := bigchain.DefaultGetTxSender(tx)
	prevRightId := req.PostFormValue("prevRightId")
	var prevTransferId string
	var right Data
	if spec.MatchId(prevRightId) {
		right, err = ld.ValidateRightId(api.id, prevRightId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		prevTransferId = spec.GetTransferId(right)
	} else {
		prevTransferId = rightToId
	}
	transferId, rightHolderIds, err := api.Transfer(rightToId, prevTransferId, rightHolderKey, rightHolderId, percentShares)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if n := len(rightHolderIds); n == 1 {
		right, err = api.SendIndividualCreateTx(1, spec.NewRight(rightHolderIds, rightToId, transferId), rightHolderKey)
	} else if n == 2 {
		right, err = api.SendMultipleOwnersCreateTx([]int{1, 1}, spec.NewRight(rightHolderIds, rightToId, transferId), []crypto.PublicKey{api.pub, rightHolderKey})
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, right)
}

func (api *Api) Transfer(assetId, consumeId string, owner crypto.PublicKey, ownerId string, transferAmount int) (transferId string, ownerIds []string, err error) {
	tx, err := bigchain.HttpGetTx(consumeId)
	if err != nil {
		return "", nil, err
	}
	if assetId != consumeId {
		if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
			return "", nil, Error("Expected TRANSFER tx")
		}
		if assetId != bigchain.GetTxAssetId(tx) {
			return "", nil, ErrorAppend(ErrInvalidId, assetId)
		}
	}
	for outputIdx, output := range bigchain.GetTxOutputs(tx) {
		if api.pub.Equals(bigchain.GetOutputPublicKey(output)) {
			totalAmount := bigchain.GetOutputAmount(output)
			keepAmount := totalAmount - transferAmount
			if keepAmount == 0 {
				ownerIds = []string{ownerId}
				transferId, err = api.SendIndividualTransferTx(transferAmount, assetId, consumeId, outputIdx, owner)
			} else if keepAmount > 0 {
				ownerIds = append([]string{api.id}, ownerId)
				transferId, err = api.SendDivisibleTransferTx([]int{keepAmount, transferAmount}, assetId, consumeId, outputIdx, owner)
			} else {
				err = Error("Cannot transfer that many shares")
			}
			if err != nil {
				return "", nil, err
			}
			return transferId, ownerIds, nil
		}
	}
	return "", nil, Error("You do not own output in consume tx")
}

func (api *Api) CompositionHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var err error
	hfaCode := req.PostFormValue("hfaCode")
	composerIds := req.PostForm["composerId"]
	inLanguage := req.PostFormValue("inLanguage")
	iswcCode := req.PostFormValue("iswcCode")
	name := req.PostFormValue("name")
	var percentShares []int
	publisherId := req.PostFormValue("publisherId")
	shares := req.PostForm["splits"]
	if len(shares) > 1 {
		percentShares = make([]int, len(shares))
		for i, share := range shares {
			percentShares[i], err = Atoi(share)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
	}
	thresholdSignature := req.PostFormValue("thresholdSignature")
	url := req.PostFormValue("url")
	composition, err := api.Composition(
		spec.NewComposition(composerIds, hfaCode, inLanguage, iswcCode, name, publisherId, thresholdSignature, url),
		percentShares,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, composition)
}

func (api *Api) RecordingHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	compositionId := req.PostFormValue("compositionId")
	artistIds := req.PostForm["artistId"]
	duration := req.PostFormValue("duration")
	file, err := req.MultipartForm.File["recording"][0].Open()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	isrcCode := req.PostFormValue("isrcCode")
	licenseId := req.PostFormValue("licenseId")
	recordLabelId := req.PostFormValue("recordLabelId")
	splits := req.PostForm["splits"]
	var percentShares []int = nil
	if len(splits) > 1 {
		percentShares = make([]int, len(splits))
		for i, split := range splits {
			percentShares[i] = MustAtoi(split)
		}
	}
	thresholdSignature := req.PostFormValue("thresholdSignature")
	url := req.PostFormValue("url")
	recording, err := api.Recording(
		file,
		percentShares,
		spec.NewRecording(artistIds, compositionId, duration, isrcCode, licenseId, recordLabelId, thresholdSignature, url),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, recording)
}

func (api *Api) LicenseHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var err error
	var license Data
	validFrom := req.PostFormValue("validFrom")
	validThrough := req.PostFormValue("validThrough")
	licenseForIds := req.PostForm["licenseForId"]
	licenseHolderIds := req.PostForm["licenseHolderId"]
	rightIds := req.PostForm["rightId"]
	if n := len(licenseHolderIds); n == 1 {
		tx, err := ld.QueryAndValidateSchema(licenseHolderIds[0], "user")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		owner := bigchain.DefaultGetTxSender(tx)
		license, err = api.SendIndividualCreateTx(1, spec.NewLicense(licenseForIds, licenseHolderIds, api.id, rightIds, validFrom, validThrough), owner)
	} else if n > 1 {
		amounts := make([]int, n)
		owners := make([]crypto.PublicKey, n)
		for i, licenseHolderId := range licenseHolderIds {
			amounts[i] = 1
			tx, err := ld.QueryAndValidateSchema(licenseHolderId, "user")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			owners[i] = bigchain.DefaultGetTxSender(tx)
		}
		license, err = api.SendMultipleOwnersCreateTx(amounts, spec.NewLicense(licenseForIds, licenseHolderIds, api.id, rightIds, validFrom, validThrough), owners)
	} else {
		err = Error("zero license-holder ids")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, license)
}

func (api *Api) SearchHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, ErrExpectedGet.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	params := req.URL.Query()
	if params.Get("action") != "search" {
		pg, _ := LoadPage("search")
		RenderTemplate(w, "search.html", pg)
		return
	}
	var models []Data
	name := params.Get("name")
	_type := params.Get("type")
	userId := params.Get("userId")
	tx, err := ld.QueryAndValidateSchema(userId, "user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pub := bigchain.DefaultGetTxSender(tx)
	switch _type {
	case "composition":
		models, err = bigchain.HttpGetFilter(func(txId string) (Data, error) {
			return CompositionFilter(txId, name)
		}, pub)
	case "license":
		models, err = bigchain.HttpGetFilter(func(txId string) (Data, error) {
			return ld.ValidateLicenseId(txId)
		}, pub)
	case "recording":
		models, err = bigchain.HttpGetFilter(func(txId string) (Data, error) {
			return RecordingFilter(txId, name)
		}, pub)
	case "right":
		models, err = bigchain.HttpGetFilter(func(txId string) (Data, error) {
			return ld.ValidateRightId(userId, txId)
		}, pub)
	case "user":
		models = []Data{bigchain.GetTxData(tx)}
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

func CompositionFilter(compositionId, name string) (Data, error) {
	composition, err := ld.ValidateCompositionId(compositionId)
	if err != nil {
		return nil, err
	}
	if !EmptyStr(name) && !MatchStr(name, spec.GetName(composition)) {
		return nil, Error("name does not match")
	}
	return composition, nil
}

func RecordingFilter(recordingId, name string) (Data, error) {
	recording, err := ld.ValidateRecordingId(recordingId)
	if err != nil {
		return nil, err
	}
	if !EmptyStr(name) {
		compositionId := spec.GetId(spec.GetRecordingOf(recording))
		if _, err = CompositionFilter(compositionId, name); err != nil {
			return nil, err
		}
	}
	return recording, nil
}

func (api *Api) ProveHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, ErrExpectedGet.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var err error
	params := req.URL.Query()
	challenge := params.Get("challenge")
	dataId := params.Get("dataId")
	var sig crypto.Signature
	_type := params.Get("type")
	userId := params.Get("userId")
	switch _type {
	case "composition":
		sig, err = ld.ProveComposer(challenge, userId, dataId, api.priv)
	case "license":
		sig, err = ld.ProveLicenseHolder(challenge, userId, dataId, api.priv)
	case "recording":
		sig, err = ld.ProveArtist(userId, challenge, api.priv, dataId)
	case "right":
		sig, err = ld.ProveRightHolder(challenge, api.priv, userId, dataId)
	default:
		err = ErrorAppend(ErrInvalidType, _type)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, sig)
}

func (api *Api) VerifyHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, ErrExpectedGet.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var err error
	params := req.URL.Query()
	challenge := params.Get("challenge")
	dataId := params.Get("dataId")
	userId := params.Get("userId")
	sig := new(ed25519.Signature)
	signature := params.Get("signature")
	if err = sig.FromString(signature); err == nil {
		_type := params.Get("type")
		switch _type {
		case "composition":
			err = ld.VerifyComposer(challenge, userId, dataId, sig)
		case "license":
			err = ld.VerifyLicenseHolder(challenge, userId, dataId, sig)
		case "recording":
			err = ld.VerifyArtist(userId, challenge, dataId, sig)
		case "right":
			err = ld.VerifyRightHolder(challenge, dataId, userId, sig)
		default:
			err = ErrorAppend(ErrInvalidType, _type)
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, "Verified proof!")
}

func (api *Api) Sign(txId string) (cc.Fulfillment, error) {
	tx, err := bigchain.HttpGetTx(txId)
	if err != nil {
		return nil, err
	}
	model := bigchain.GetTxData(tx)
	sig := api.priv.Sign(Checksum256(MustMarshalJSON(model)))
	return cc.DefaultFulfillmentEd25519(
		api.pub.(*ed25519.PublicKey),
		sig.(*ed25519.Signature),
	), nil
}

func Threshold(thresholdSignatures []string) (cc.Fulfillment, error) {
	var err error
	subs := make(cc.Fulfillments, len(thresholdSignatures))
	for i, thresholdSignature := range thresholdSignatures {
		subs[i], err = cc.DefaultUnmarshalURI(thresholdSignature)
		if err != nil {
			return nil, err
		}
	}
	return cc.DefaultFulfillmentThreshold(subs), nil
}

/*

func (api *Api) ReleaseHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, ErrExpectedPost.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	name := req.PostFormValue("name")
	recordingIds := SplitStr(req.PostFormValue("recordingIds"), ",")
	recordLabelId := req.PostFormValue("recordLabelId")
	rightIds := SplitStr(req.PostFormValue("rightIds"), ",")
	url := req.PostFormValue("url")
	release, err := api.DefaultSendIndividualCreateTx(spec.NewRelease(name, recordingIds, recordLabelId, rightIds, url))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, release)
}

func (api *Api) SignHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, ErrExpectedGet.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	pg, _ := LoadPage("sign")
	RenderTemplate(w, "sign.html", pg)
	params := req.URL.Query()
	txId := params.Get("txId")
	ful, err := api.Sign(txId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, ful.String())
}

func (api *Api) ThresholdHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		http.Error(w, ErrExpectedGet.Error(), http.StatusBadRequest)
		return
	}
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	pg, _ := LoadPage("threshold")
	RenderTemplate(w, "threshold.html", pg)
	thresholdSignatures := SplitStr(params.Get("thresholdSignatures"), ",")
	ful, err := Threshold(thresholdSignatures)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, ful.String())
}

*/

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
	tx, err := ld.QueryAndValidateSchema(id, "user")
	if err != nil {
		return err
	}
	user := bigchain.GetTxData(tx)
	pub := bigchain.DefaultGetTxSender(tx)
	if !pub.Equals(priv.Public()) {
		return ErrInvalidKey
	}
	api.logger.Info(Sprintf("SUCCESS %s is logged in", spec.GetName(user)))
	api.id = id
	api.priv, api.pub = priv, pub
	return nil
}

func (api *Api) Register(user Data, password, path string) (Data, error) {
	file, err := CreateFile(path + "/credentials.json")
	if err != nil {
		return nil, err
	}
	api.priv, api.pub = ed25519.GenerateKeypairFromPassword(password)
	user, err = api.DefaultSendIndividualCreateTx(user)
	if err != nil {
		return nil, err
	}
	credentials := Data{
		"id":         bigchain.GetId(user),
		"privateKey": api.priv.String(),
		"publicKey":  api.pub.String(),
	}
	api.priv, api.pub = nil, nil
	WriteJSON(file, credentials)
	return credentials, nil
}

func (api *Api) Composition(composition Data, percentShares []int) (Data, error) {
	composers := spec.GetComposers(composition)
	n := len(composers)
	composerKeys := make([]crypto.PublicKey, n)
	for i, composer := range composers {
		tx, err := ld.QueryAndValidateSchema(spec.GetId(composer), "user")
		if err != nil {
			return nil, err
		}
		composerKeys[i] = bigchain.DefaultGetTxSender(tx)
	}
	if n == 1 {
		return api.SendIndividualCreateTx(100, composition, composerKeys[0])
	}
	return api.SendMultipleOwnersCreateTx(percentShares, composition, composerKeys)
}

func (api *Api) Recording(file io.Reader, percentShares []int, recording Data) (Data, error) {
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
		tx, err := ld.QueryAndValidateSchema(spec.GetId(artist), "user")
		if err != nil {
			return nil, err
		}
		artistKeys[i] = bigchain.DefaultGetTxSender(tx)
	}
	if n == 1 {
		return api.SendIndividualCreateTx(100, recording, artistKeys[0])
	}
	return api.SendMultipleOwnersCreateTx(percentShares, recording, artistKeys)
}
