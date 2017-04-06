package api

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/zbo14/envoke/bigchain"
	. "github.com/zbo14/envoke/common"
	"github.com/zbo14/envoke/crypto/crypto"
	"github.com/zbo14/envoke/crypto/ed25519"
	ld "github.com/zbo14/envoke/linked_data"
	"github.com/zbo14/envoke/spec"
)

var (
	ErrBigchain   = Error("Bigchain Error")
	ErrCrypto     = Error("Crypto Error")
	ErrSpec       = Error("Spec Error")
	ErrValidation = Error("Validation Error")
)

type Api struct {
	logger  Logger
	privkey crypto.PrivateKey
	pubkey  crypto.PublicKey
	userId  string
}

func NewApi() *Api {
	return &Api{
		logger: NewLogger("api"),
	}
}

func (api *Api) AddRoutes(router *httprouter.Router) {
	router.POST("/license", api.LicenseHandler)
	router.POST("/login", api.LoginHandler)
	router.POST("/publish", api.PublishHandler)
	router.POST("/release", api.ReleaseHandler)
	router.POST("/register", api.RegisterHandler)
	router.POST("/right", api.RightHandler)
	router.POST("/sign/:type", api.SignHandler)

	router.GET("/query/:id", api.QueryHandler)
	router.GET("/search/:type/:userId", api.SearchHandler)
	router.GET("/search/:type/:userId/:name", api.SearchNameHandler)

	// should these be POST..?
	router.GET("/prove/:challenge/:txId/:type/:userId", api.ProveHandler)
	router.GET("/verify/:challenge/:signature/:txId/:type/:userId", api.VerifyHandler)
}

func (api *Api) LoginHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	privateKey := req.PostFormValue("privateKey")
	userId := req.PostFormValue("userId")
	if err := api.Login(privateKey, userId); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func UserFromRequest(req *http.Request) (Data, error) {
	email := req.PostFormValue("email")
	ipiNumer := req.PostFormValue("ipiNumber")
	isniNumber := req.PostFormValue("isniNumber")
	memberIds := req.PostForm["memberIds"]
	name := req.PostFormValue("name")
	pro := req.PostFormValue("pro")
	sameAs := req.PostFormValue("sameAs")
	_type := req.PostFormValue("type")
	user, err := spec.NewUser(email, ipiNumer, isniNumber, memberIds, name, pro, sameAs, _type)
	if err != nil {
		return nil, ErrorJoin(ErrSpec, err)
	}
	return user, nil
}

func (api *Api) RegisterHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	password := req.PostFormValue("password")
	user, err := UserFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	credentials, err := api.Register(password, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, credentials)
}

func (api *Api) RightHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	percentShares, err := Atoi(req.PostFormValue("percentShares"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	prevRightId := req.PostFormValue("prevRightId")
	recipientId := req.PostFormValue("recipientId")
	rightToId := req.PostFormValue("rightToId")
	id, err := api.Right(percentShares, prevRightId, recipientId, rightToId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte(id))
}

func (api *Api) Right(percentShares int, prevRightId, recipientId, rightToId string) (string, error) {
	tx, err := ld.BuildRightTx(percentShares, prevRightId, api.privkey, recipientId, rightToId, api.userId, api.pubkey)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	id, err := api.SignAndSendTx(tx)
	if err != nil {
		return "", err
	}
	return id, nil
}

func CompositionFromRequest(req *http.Request) (Data, error) {
	inLanguage := req.PostFormValue("inLanguage")
	composerIds := req.PostForm["composerIds"]
	iswcCode := req.PostFormValue("iswcCode")
	name := req.PostFormValue("name")
	publisherId := req.PostFormValue("publisherId")
	url := req.PostFormValue("url")
	composition, err := spec.NewComposition(composerIds, inLanguage, iswcCode, name, publisherId, url)
	if err != nil {
		return nil, ErrorJoin(ErrSpec, err)
	}
	return composition, nil
}

func SplitsFromRequest(req *http.Request) (splits []int, err error) {
	// form should have been parsed
	n := len(req.PostForm["splits"])
	if n == 0 {
		return nil, nil
	}
	if n == 1 {
		return nil, Error("must have more than one split")
	}
	splits = make([]int, n)
	for i, split := range req.PostForm["splits"] {
		splits[i], err = Atoi(split)
		if err != nil {
			return nil, err
		}
	}
	return splits, nil
}

func SignaturesFromRequest(req *http.Request) ([]string, error) {
	signatures := req.PostForm["signatures"]
	n := len(signatures)
	if n == 0 {
		return nil, nil
	}
	if n == 1 {
		return nil, Error("must have more than one signature")
	}
	return signatures, nil
}

func (api *Api) Publish(composition Data, signatures []string, splits []int) (string, error) {
	tx, err := ld.BuildCompositionTx(composition, signatures, splits)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	id, err := api.SignAndSendTx(tx)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (api *Api) PublishHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	composition, err := CompositionFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	signatures, err := SignaturesFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	splits, err := SplitsFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := api.Publish(composition, signatures, splits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte(id))
}

func RecordingFromRequest(req *http.Request) (Data, error) {
	compositionId := req.PostFormValue("compositionId")
	artistIds := req.PostForm["artistIds"]
	duration := req.PostFormValue("duration")
	isrcCode := req.PostFormValue("isrcCode")
	licenseId := req.PostFormValue("licenseId")
	recordLabelId := req.PostFormValue("recordLabelId")
	url := req.PostFormValue("url")
	recording, err := spec.NewRecording(artistIds, compositionId, duration, isrcCode, licenseId, recordLabelId, url)
	if err != nil {
		return nil, ErrorJoin(ErrSpec, err)
	}
	return recording, nil
}

func (api *Api) ReleaseHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	recording, err := RecordingFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	signatures, err := SignaturesFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	splits, err := SplitsFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := api.Release(recording, signatures, splits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte(id))
}

func (api *Api) Release(recording Data, signatures []string, splits []int) (string, error) {
	tx, err := ld.BuildRecordingTx(recording, signatures, splits)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	id, err := api.SignAndSendTx(tx)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (api *Api) License(license Data) (string, error) {
	tx, err := ld.BuildLicenseTx(license, api.pubkey)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	id, err := api.SignAndSendTx(tx)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (api *Api) LicenseHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	validFrom := req.PostFormValue("validFrom")
	validThrough := req.PostFormValue("validThrough")
	licenseForIds := req.PostForm["licenseForIds"]
	licenseHolderIds := req.PostForm["licenseHolderIds"]
	rightIds := req.PostForm["rightId"]
	license, err := spec.NewLicense(licenseForIds, licenseHolderIds, api.userId, rightIds, validFrom, validThrough)
	if err != nil {
		http.Error(w, ErrorJoin(ErrSpec, err).Error(), http.StatusBadRequest)
		return
	}
	id, err := api.License(license)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte(id))
}

func (api *Api) QueryHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	id := params.ByName("id")
	if !spec.MatchId(id) {
		http.Error(w, ErrorAppend(ErrInvalidId, id).Error(), http.StatusBadRequest)
		return
	}
	tx, err := bigchain.HttpGetTx(id)
	if err != nil {
		http.Error(w, ErrorJoin(ErrBigchain, err).Error(), http.StatusBadRequest)
		return
	}
	data := bigchain.GetTxAssetData(tx)
	switch _type := spec.GetType(data); _type {
	case "License":
		err = ld.ValidateLicenseTx(tx)
	case "MusicComposition":
		err = ld.ValidateCompositionTx(tx)
	case "MusicRecording":
		err = ld.ValidateRecordingTx(tx)
	case "Right":
		err = ld.ValidateRightTx(tx)
	case "User":
		err = ld.ValidateUserTx(tx)
	default:
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, ErrorJoin(ErrValidation, err).Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, data)
}

func (api *Api) SearchHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var datas []Data
	_type := params.ByName("type")
	userId := params.ByName("userId")
	tx, err := ld.ValidateUserId(userId)
	if err != nil {
		http.Error(w, ErrorJoin(ErrValidation, err).Error(), http.StatusBadRequest)
		return
	}
	pubkey := bigchain.DefaultTxOwnerBefore(tx)
	switch _type {
	case "composition":
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return ld.ValidateCompositionId(id)
		}, pubkey)
	case "license":
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return ld.ValidateLicenseId(id)
		}, pubkey)
	case "recording":
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return ld.ValidateRecordingId(id)
		}, pubkey)
	case "right":
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return ld.ValidateRightId(id)
		}, pubkey)
	case "user":
		datas = []Data{bigchain.GetTxAssetData(tx)}
	default:
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, ErrorJoin(ErrBigchain, err).Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, datas)
}

func (api *Api) SearchNameHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var datas []Data
	name := params.ByName("name")
	_type := params.ByName("type")
	userId := params.ByName("userId")
	tx, err := ld.ValidateUserId(userId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pubkey := bigchain.DefaultTxOwnerBefore(tx)
	if _type == "composition" {
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return CompositionFilter(id, name)
		}, pubkey)
	} else if _type == "recording" {
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return RecordingFilter(name, id)
		}, pubkey)
	} else {
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, ErrorJoin(ErrBigchain, err).Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, datas)
}

func CompositionFilter(compositionId, name string) (Data, error) {
	tx, err := ld.ValidateCompositionId(compositionId)
	if err != nil {
		return nil, ErrorJoin(ErrValidation, err)
	}
	if !MatchStr(name, spec.GetName(bigchain.GetTxAssetData(tx))) {
		return nil, Error("name does not match")
	}
	return tx, nil
}

func RecordingFilter(name, recordingId string) (Data, error) {
	tx, err := ld.ValidateRecordingId(recordingId)
	if err != nil {
		return nil, ErrorJoin(ErrValidation, err)
	}
	compositionId := spec.GetId(spec.GetRecordingOf(bigchain.GetTxAssetData(tx)))
	if _, err = CompositionFilter(compositionId, name); err != nil {
		return nil, err
	}
	return tx, nil
}

func (api *Api) ProveHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var err error
	challenge := params.ByName("challenge")
	var sig crypto.Signature
	txId := params.ByName("txId")
	_type := params.ByName("type")
	userId := params.ByName("userId")
	switch _type {
	case "composition":
		sig, err = ld.ProveComposer(challenge, userId, txId, api.privkey)
	case "license":
		sig, err = ld.ProveLicenseHolder(challenge, userId, txId, api.privkey)
	case "recording":
		sig, err = ld.ProveArtist(userId, challenge, api.privkey, txId)
	case "right":
		sig, err = ld.ProveRightHolder(challenge, api.privkey, userId, txId)
	default:
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, ErrorJoin(ErrValidation, err).Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte(sig.String()))
}

func (api *Api) VerifyHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var err error
	challenge := params.ByName("challenge")
	txId := params.ByName("txId")
	userId := params.ByName("userId")
	sig := new(ed25519.Signature)
	signature := params.ByName("signature")
	if err = sig.FromString(signature); err == nil {
		_type := params.ByName("type")
		switch _type {
		case "composition":
			err = ld.VerifyComposer(challenge, userId, txId, sig)
		case "license":
			err = ld.VerifyLicenseHolder(challenge, userId, txId, sig)
		case "recording":
			err = ld.VerifyArtist(userId, challenge, txId, sig)
		case "right":
			err = ld.VerifyRightHolder(challenge, txId, userId, sig)
		default:
			http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
			return
		}
	}
	if err != nil {
		http.Error(w, ErrorJoin(ErrValidation, err).Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (api *Api) SignHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	if _type := params.ByName("type"); _type == "composition" {
		composition, err := CompositionFromRequest(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		splits, err := SplitsFromRequest(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		signature, err := api.SignComposition(composition, splits)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte(signature))
	} else if _type == "recording" {
		recording, err := RecordingFromRequest(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		splits, err := SplitsFromRequest(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		signature, err := api.SignRecording(recording, splits)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write([]byte(signature))
	} else {
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
	}
}

func (api *Api) SignComposition(composition Data, splits []int) (string, error) {
	tx, err := ld.BuildCompositionTx(composition, nil, splits)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	return api.Sign(tx), nil
}

func (api *Api) SignRecording(recording Data, splits []int) (string, error) {
	tx, err := ld.BuildRecordingTx(recording, nil, splits)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	return api.Sign(tx), nil
}

func (api *Api) Sign(data Data) string {
	return api.privkey.Sign(Checksum256(MustMarshalJSON(data))).String()
}

func (api *Api) LoggedIn() bool {
	switch {
	case api.privkey == nil:
		api.logger.Warn("Private-key is not set")
	case api.pubkey == nil:
		api.logger.Warn("Public-key is not set")
	case api.userId == "":
		api.logger.Warn("ID is not set")
	default:
		return true
	}
	api.logger.Error("LOGIN FAILED")
	return false
}

func (api *Api) SignAndSendTx(tx Data) (string, error) {
	bigchain.FulfillTx(tx, api.privkey)
	if !bigchain.FulfilledTx(tx) {
		return "", ErrorJoin(ErrBigchain, ErrInvalidFulfillment)
	}
	id, err := bigchain.HttpPostTx(tx)
	if err != nil {
		return "", ErrorJoin(ErrBigchain, err)
	}
	operation := bigchain.GetTxOperation(tx)
	if operation == bigchain.CREATE {
		api.logger.Info("SUCCESS sent CREATE tx with " + spec.GetType(bigchain.GetTxAssetData(tx)))
	} else if operation == bigchain.TRANSFER {
		api.logger.Info("SUCCESS sent TRANSFER tx")
	} else {
		return "", ErrorJoin(ErrBigchain, Error("invalid operation: "+operation))
	}
	return id, nil
}

func (api *Api) Login(privstr, userId string) error {
	privkey := new(ed25519.PrivateKey)
	if err := privkey.FromString(privstr); err != nil {
		return ErrorJoin(ErrCrypto, err)
	}
	tx, err := ld.ValidateUserId(userId)
	if err != nil {
		return ErrorJoin(ErrValidation, err)
	}
	pubkey := bigchain.DefaultTxOwnerBefore(tx)
	if !pubkey.Equals(privkey.Public()) {
		return ErrInvalidKey // what should prepend be?
	}
	api.logger.Info(Sprintf("SUCCESS %s is logged in", spec.GetName(bigchain.GetTxAssetData(tx))))
	api.privkey, api.pubkey = privkey, pubkey
	api.userId = userId
	return nil
}

func (api *Api) Register(password string, user Data) (Data, error) {
	api.privkey, api.pubkey = ed25519.GenerateKeypairFromPassword(password)
	tx, err := bigchain.IndividualCreateTx(1, user, api.pubkey, api.pubkey)
	if err != nil {
		return nil, ErrorJoin(ErrBigchain, err)
	}
	id, err := api.SignAndSendTx(tx)
	if err != nil {
		return nil, err
	}
	credentials := Data{
		"privateKey": api.privkey.String(),
		"publicKey":  api.pubkey.String(),
		"userId":     id,
	}
	api.privkey, api.pubkey = nil, nil
	return credentials, nil
}
