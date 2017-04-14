package api

import (
	"net/http"
	"time"

	"github.com/Envoke-org/envoke-api/bigchain"
	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
	ld "github.com/Envoke-org/envoke-api/linked_data"
	"github.com/Envoke-org/envoke-api/spec"
	"github.com/julienschmidt/httprouter"
)

const MAX_MEMORY = 1000000

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
	router.GET("/prove/:challenge/:txId/:type", api.ProveHandler)
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
	isniNumber := req.PostFormValue("isniNumber")
	memberIds := req.PostForm["memberIds"]
	name := req.PostFormValue("name")
	sameAs := req.PostFormValue("sameAs")
	_type := req.PostFormValue("type")
	user, err := spec.NewUser(email, isniNumber, memberIds, name, sameAs, _type)
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
	assetId := req.PostFormValue("assetId")
	recipientIds := req.PostForm["recipientIds"]
	splits := make([]int, len(req.PostForm["splits"]))
	var err error
	for i, split := range req.PostForm["splits"] {
		splits[i], err = Atoi(split)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	id, err := api.Right(assetId, recipientIds, splits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte(id))
}

func (api *Api) Right(assetId string, recipientIds []string, splits []int) (string, error) {
	tx, err := ld.AssembleRightTx(assetId, api.privkey, api.pubkey, recipientIds, splits)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	return api.SendTx(tx)
}

func CompositionFromRequest(req *http.Request) (Data, error) {
	inLanguage := req.PostFormValue("inLanguage")
	composerIds := req.PostForm["composerIds"]
	iswcCode := req.PostFormValue("iswcCode")
	name := req.PostFormValue("name")
	publisherIds := req.PostForm["publisherIds"]
	url := req.PostFormValue("url")
	composition, err := spec.NewComposition(composerIds, inLanguage, iswcCode, name, publisherIds, url)
	if err != nil {
		return nil, ErrorJoin(ErrSpec, err)
	}
	return composition, nil
}

func SplitsFromRequest(req *http.Request) (splits []int, err error) {
	// form should have been parsed
	n := len(req.PostForm["splits"])
	if n <= 1 {
		return []int{100}, nil
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
	tx, err := ld.AssembleCompositionTx(composition, api.privkey, signatures, splits)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	return api.SendTx(tx)
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
	licenseIds := req.PostForm["licenseIds"]
	recordLabelIds := req.PostForm["recordLabelIds"]
	url := req.PostFormValue("url")
	recording, err := spec.NewRecording(artistIds, compositionId, duration, isrcCode, licenseIds, recordLabelIds, url)
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
	tx, err := ld.AssembleRecordingTx(api.privkey, recording, signatures, splits)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	return api.SendTx(tx)
}

func (api *Api) License(assetIds []string, expireTimes []time.Time, licenseHolderIds []string) (string, error) {
	tx, err := ld.AssembleLicenseTx(assetIds, expireTimes, licenseHolderIds, api.privkey, api.pubkey)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	return api.SendTx(tx)
}

func (api *Api) LicenseHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	err := req.ParseMultipartForm(MAX_MEMORY)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	assetIds := req.PostForm["assetIds"]
	expireTimes := make([]time.Time, len(req.PostForm["expireTimes"]))
	for i, expireTime := range req.PostForm["expireTimes"] {
		expireTimes[i], err = ParseDate(expireTime)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	licenseHolderIds := req.PostForm["licenseHolderIds"]
	id, err := api.License(assetIds, expireTimes, licenseHolderIds)
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
	case "MusicGroup", "Organization", "Person":
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
		}, pubkey, false)
	case "license":
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return ld.ValidateLicenseId(id)
		}, pubkey, false)
	case "recording":
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return ld.ValidateRecordingId(id)
		}, pubkey, false)
	case "right":
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return ld.ValidateRightId(id)
		}, pubkey, false)
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
		}, pubkey, false)
	} else if _type == "recording" {
		datas, err = bigchain.HttpGetFilter(func(id string) (Data, error) {
			return RecordingFilter(name, id)
		}, pubkey, false)
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
	compositionId := spec.GetRecordingOfId(bigchain.GetTxAssetData(tx))
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
	switch _type {
	case "artist":
		sig, err = ld.ProveArtist(api.userId, challenge, api.privkey, txId)
	case "composer":
		sig, err = ld.ProveComposer(challenge, api.userId, txId, api.privkey)
	case "license-holder":
		sig, err = ld.ProveLicenseHolder(challenge, api.userId, txId, api.privkey)
	case "publisher":
		sig, err = ld.ProvePublisher(challenge, txId, api.privkey, api.userId)
	case "record-label":
		sig, err = ld.ProveRecordLabel(challenge, api.privkey, txId, api.userId)
	case "right-holder":
		sig, err = ld.ProveRightHolder(challenge, api.privkey, api.userId, txId)
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
		case "artist":
			err = ld.VerifyArtist(userId, challenge, txId, sig)
		case "composer":
			err = ld.VerifyComposer(challenge, userId, txId, sig)
		case "license-holder":
			err = ld.VerifyLicenseHolder(challenge, userId, txId, sig)
		case "publisher":
			err = ld.VerifyPublisher(challenge, txId, userId, sig)
		case "record-label":
			err = ld.VerifyRecordLabel(challenge, txId, userId, sig)
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
	tx, err := ld.AssembleCompositionTx(composition, nil, nil, splits)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	return api.Sign(tx), nil
}

func (api *Api) SignRecording(recording Data, splits []int) (string, error) {
	tx, err := ld.AssembleRecordingTx(nil, recording, nil, splits)
	if err != nil {
		return "", ErrorJoin(ErrValidation, err)
	}
	return api.Sign(tx), nil
}

func (api *Api) Sign(data Data) string {
	return api.privkey.Sign(MustMarshalJSON(data)).String()
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

func (api *Api) SendTx(tx Data) (string, error) {
	fulfilled, err := bigchain.FulfilledTx(tx)
	if err != nil {
		return "", ErrorJoin(ErrBigchain, err)
	}
	if !fulfilled {
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
	tx, err := bigchain.CreateTx([]int{1}, user, nil, []crypto.PublicKey{api.pubkey}, []crypto.PublicKey{api.pubkey})
	if err != nil {
		return nil, ErrorJoin(ErrBigchain, err)
	}
	if err = bigchain.IndividualFulfillTx(tx, api.privkey, NilTime); err != nil {
		return nil, ErrorJoin(ErrBigchain, err)
	}
	userId, err := api.SendTx(tx)
	if err != nil {
		return nil, err
	}
	credentials := Data{
		"privateKey": api.privkey.String(),
		"publicKey":  api.pubkey.String(),
		"userId":     userId,
	}
	api.privkey, api.pubkey = nil, nil
	return credentials, nil
}
