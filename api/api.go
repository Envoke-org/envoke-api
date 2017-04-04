package api

import (
	"io"
	"net/http"

	// "github.com/dhowden/tag"
	"github.com/julienschmidt/httprouter"
	"github.com/zbo14/envoke/bigchain"
	. "github.com/zbo14/envoke/common"
	cc "github.com/zbo14/envoke/crypto/conditions"
	"github.com/zbo14/envoke/crypto/crypto"
	"github.com/zbo14/envoke/crypto/ed25519"
	ld "github.com/zbo14/envoke/linked_data"
	"github.com/zbo14/envoke/spec"
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

func UserFromRequest(req *http.Request) Data {
	email := req.PostFormValue("email")
	ipiNumer := req.PostFormValue("ipiNumber")
	isniNumber := req.PostFormValue("isniNumber")
	memberIds := req.PostForm["memberId"]
	name := req.PostFormValue("name")
	pro := req.PostFormValue("pro")
	sameAs := req.PostFormValue("sameAs")
	_type := req.PostFormValue("type")
	return spec.NewUser(email, ipiNumer, isniNumber, memberIds, name, pro, sameAs, _type)
}

func (api *Api) RegisterHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	password := req.PostFormValue("password")
	user := UserFromRequest(req)
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
	rightHolderId := req.PostFormValue("rightHolderId")
	tx, err := ld.ValidateUserId(rightHolderId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rightHolderKey := bigchain.DefaultTxOwnerBefore(tx)
	rightToId := req.PostFormValue("rightToId")
	prevRightId := req.PostFormValue("prevRightId")
	var prevTransferId string
	if spec.MatchId(prevRightId) {
		if _, tx, err = ld.CheckRightHolder(api.userId, prevRightId); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		prevTransferId = spec.GetTransferId(bigchain.GetTxAssetData(tx))
	} else {
		prevTransferId = rightToId
	}
	rightHolderIds, transferId, err := api.Transfer(rightToId, prevTransferId, rightHolderKey, rightHolderId, percentShares)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	right, err := spec.NewRight(rightHolderIds, rightToId, transferId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(rightHolderIds) == 1 {
		right, err = api.SendIndividualCreateTx(1, right, rightHolderKey)
	} else {
		right, err = api.SendMultipleOwnersCreateTx([]int{1, 1}, right, []crypto.PublicKey{api.pubkey, rightHolderKey})
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, right)
}

func (api *Api) Transfer(assetId, consumeId string, owner crypto.PublicKey, ownerId string, transferAmount int) (ownerIds []string, transferId string, err error) {
	tx, err := bigchain.HttpGetTx(consumeId)
	if err != nil {
		return nil, "", err
	}
	if assetId != consumeId {
		if bigchain.TRANSFER != bigchain.GetTxOperation(tx) {
			return nil, "", Error("Expected TRANSFER tx")
		}
		if assetId != bigchain.GetTxAssetId(tx) {
			return nil, "", ErrorAppend(ErrInvalidId, assetId)
		}
	}
	for outputIdx, output := range bigchain.GetTxOutputs(tx) {
		if api.pubkey.Equals(bigchain.DefaultOutputOwnerAfter(output)) {
			totalAmount := bigchain.GetOutputAmount(output)
			keepAmount := totalAmount - transferAmount
			if keepAmount == 0 {
				ownerIds = []string{ownerId}
				transferId, err = api.SendIndividualTransferTx(transferAmount, assetId, consumeId, outputIdx, owner)
			} else if keepAmount > 0 {
				ownerIds = append([]string{api.userId}, ownerId)
				transferId, err = api.SendDivisibleTransferTx([]int{keepAmount, transferAmount}, assetId, consumeId, outputIdx, owner)
			} else {
				err = Error("Cannot transfer that many shares")
			}
			if err != nil {
				return nil, "", err
			}
			return ownerIds, transferId, nil
		}
	}
	return nil, "", Error("You do not own output in consume tx")
}

func CompositionFromRequest(req *http.Request) (Data, error) {
	inLanguage := req.PostFormValue("inLanguage")
	composerIds := req.PostForm["composerId"]
	iswcCode := req.PostFormValue("iswcCode")
	name := req.PostFormValue("name")
	publisherId := req.PostFormValue("publisherId")
	url := req.PostFormValue("url")
	return spec.NewComposition(composerIds, inLanguage, iswcCode, name, publisherId, url)
}

func PercentSharesFromRequest(req *http.Request) (percentShares []int, err error) {
	splits := req.PostForm["split"]
	n := len(splits)
	if n == 0 {
		return nil, nil
	}
	if n == 1 {
		return nil, Error("must have more than one split")
	}
	percentShares = make([]int, n)
	for i, split := range splits {
		percentShares[i], err = Atoi(split)
		if err != nil {
			return nil, err
		}
	}
	return percentShares, nil
}

func SignaturesFromRequest(req *http.Request) ([]string, error) {
	signatures := req.PostForm["signature"]
	n := len(signatures)
	if n == 0 {
		return nil, nil
	}
	if n == 1 {
		return nil, Error("must have more than one signature")
	}
	return signatures, nil
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
	percentShares, err := PercentSharesFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	signatures, err := SignaturesFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	composition, err = api.Publish(composition, percentShares, signatures)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, composition)
}

func RecordingFromRequest(req *http.Request) (Data, error) {
	compositionId := req.PostFormValue("compositionId")
	artistIds := req.PostForm["artistId"]
	duration := req.PostFormValue("duration")
	isrcCode := req.PostFormValue("isrcCode")
	licenseId := req.PostFormValue("licenseId")
	recordLabelId := req.PostFormValue("recordLabelId")
	url := req.PostFormValue("url")
	return spec.NewRecording(artistIds, compositionId, duration, isrcCode, licenseId, recordLabelId, url)
}

func (api *Api) ReleaseHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	file, _, err := req.FormFile("recording")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	percentShares, err := PercentSharesFromRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	recording, err = api.Release(file, percentShares, recording, signatures)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, recording)
}

func (api *Api) LicenseHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	validFrom := req.PostFormValue("validFrom")
	validThrough := req.PostFormValue("validThrough")
	licenseForIds := req.PostForm["licenseForId"]
	licenseHolderIds := req.PostForm["licenseHolderId"]
	rightIds := req.PostForm["rightId"]
	license, err := spec.NewLicense(licenseForIds, licenseHolderIds, api.userId, rightIds, validFrom, validThrough)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, licenseForId := range licenseForIds {
		if _, err = ld.CheckComposerArtist(api.userId, licenseForId); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if n := len(licenseHolderIds); n == 1 {
		tx, err := ld.ValidateUserId(licenseHolderIds[0])
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		license, err = api.SendIndividualCreateTx(1, license, bigchain.DefaultTxOwnerBefore(tx))
	} else {
		amounts := make([]int, n)
		owners := make([]crypto.PublicKey, n)
		for i, licenseHolderId := range licenseHolderIds {
			amounts[i] = 1
			tx, err := ld.ValidateUserId(licenseHolderId)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			owners[i] = bigchain.DefaultTxOwnerBefore(tx)
		}
		license, err = api.SendMultipleOwnersCreateTx(amounts, license, owners)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, license)
}

func (api *Api) SearchHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var datas []Data
	_type := params.ByName("type")
	userId := params.ByName("userId")
	tx, err := ld.QueryAndValidateSchema(userId, "user")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		err = ErrorAppend(ErrInvalidType, _type)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		err = ErrorAppend(ErrInvalidType, _type)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, datas)
}

func CompositionFilter(compositionId, name string) (Data, error) {
	tx, err := ld.ValidateCompositionId(compositionId)
	if err != nil {
		return nil, err
	}
	if !MatchStr(name, spec.GetName(bigchain.GetTxAssetData(tx))) {
		return nil, Error("name does not match")
	}
	return tx, nil
}

func RecordingFilter(name, recordingId string) (Data, error) {
	tx, err := ld.ValidateRecordingId(recordingId)
	if err != nil {
		return nil, err
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
	txId := params.ByName("txId")
	var sig crypto.Signature
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
		err = ErrorAppend(ErrInvalidType, _type)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, sig)
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
			err = ErrorAppend(ErrInvalidType, _type)
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, "Verified proof!")
}

func (api *Api) SignHandler(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if !api.LoggedIn() {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}
	var data Data
	var err error
	_type := params.ByName("type")
	if _type == "composition" {
		data, err = CompositionFromRequest(req)
	} else if _type == "recording" {
		data, err = RecordingFromRequest(req)
	} else {
		err = ErrorAppend(ErrInvalidType, _type)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, api.Sign(data))
}

func (api *Api) Sign(data Data) crypto.Signature {
	return api.privkey.Sign(Checksum256(MustMarshalJSON(data)))
}

func Threshold(data Data, pubkeys []crypto.PublicKey, signatures []string) (cc.Fulfillment, error) {
	n := len(pubkeys)
	if n != len(signatures) {
		return nil, ErrorAppend(ErrInvalidSize, "slices are different sizes")
	}
	p := Checksum256(MustMarshalJSON(data))
	sig := new(ed25519.Signature)
	subs := make(cc.Fulfillments, n)
	for i, pubkey := range pubkeys {
		if err := sig.FromString(signatures[i]); err != nil {
			return nil, err
		}
		if !pubkey.Verify(p, sig) {
			return nil, ErrorAppend(ErrInvalidSignature, sig.String())
		}
		subs[i] = cc.DefaultFulfillmentEd25519(pubkey.(*ed25519.PublicKey), sig)
	}
	return cc.DefaultFulfillmentThreshold(subs), nil
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

func (api *Api) DefaultSendIndividualCreateTx(data Data) (Data, error) {
	return api.SendIndividualCreateTx(1, data, api.pubkey)
}

func (api *Api) SendIndividualCreateTx(amount int, data Data, owner crypto.PublicKey) (Data, error) {
	_type := spec.GetType(data)
	tx := bigchain.IndividualCreateTx(amount, data, owner, api.pubkey)
	bigchain.FulfillTx(tx, api.privkey)
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
	tx := bigchain.MultipleOwnersCreateTx(amounts, data, owners, api.pubkey)
	bigchain.FulfillTx(tx, api.privkey)
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
	tx := bigchain.IndividualTransferTx(amount, assetId, consumeId, outputIdx, owner, api.pubkey)
	bigchain.FulfillTx(tx, api.privkey)
	id, err := bigchain.HttpPostTx(tx)
	if err != nil {
		return "", err
	}
	api.logger.Info("SUCCESS sent TRANSFER tx")
	return id, nil
}

func (api *Api) SendDivisibleTransferTx(amounts []int, assetId, consumeId string, outputIdx int, owner crypto.PublicKey) (string, error) {
	tx := bigchain.DivisibleTransferTx(amounts, assetId, consumeId, outputIdx, []crypto.PublicKey{api.pubkey, owner}, api.pubkey)
	bigchain.FulfillTx(tx, api.privkey)
	id, err := bigchain.HttpPostTx(tx)
	if err != nil {
		return "", err
	}
	api.logger.Info("SUCCESS sent TRANSFER tx")
	return id, nil
}

func (api *Api) Login(privstr, userId string) error {
	privkey := new(ed25519.PrivateKey)
	if err := privkey.FromString(privstr); err != nil {
		return err
	}
	tx, err := ld.ValidateUserId(userId)
	if err != nil {
		return err
	}
	user := bigchain.GetTxAssetData(tx)
	pubkey := bigchain.DefaultTxOwnerBefore(tx)
	if !pubkey.Equals(privkey.Public()) {
		return ErrorAppend(ErrInvalidKey, pubkey.String())
	}
	api.logger.Info(Sprintf("SUCCESS %s is logged in", spec.GetName(user)))
	api.privkey, api.pubkey = privkey, pubkey
	api.userId = userId
	return nil
}

func (api *Api) Register(password string, user Data) (Data, error) {
	api.privkey, api.pubkey = ed25519.GenerateKeypairFromPassword(password)
	user, err := api.DefaultSendIndividualCreateTx(user)
	if err != nil {
		return nil, err
	}
	credentials := Data{
		"privateKey": api.privkey.String(),
		"publicKey":  api.pubkey.String(),
		"userId":     user.GetStr("id"),
	}
	api.privkey, api.pubkey = nil, nil
	return credentials, nil
}

func (api *Api) Publish(composition Data, percentShares []int, signatures []string) (Data, error) {
	composers := spec.GetComposers(composition)
	n := len(composers)
	composerKeys := make([]crypto.PublicKey, n)
	for i, composer := range composers {
		tx, err := ld.ValidateUserId(spec.GetId(composer))
		if err != nil {
			return nil, err
		}
		composerKeys[i] = bigchain.DefaultTxOwnerBefore(tx)
	}
	if signatures != nil {
		thresholdFulfillment, err := Threshold(composition, composerKeys, signatures)
		if err != nil {
			return nil, err
		}
		composition.Set("thresholdSignature", thresholdFulfillment.String())
	}
	if n == 1 {
		return api.SendIndividualCreateTx(100, composition, composerKeys[0])
	}
	return api.SendMultipleOwnersCreateTx(percentShares, composition, composerKeys)
}

func (api *Api) Release(file io.Reader, percentShares []int, recording Data, signatures []string) (Data, error) {
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
		tx, err := ld.ValidateUserId(spec.GetId(artist))
		if err != nil {
			return nil, err
		}
		artistKeys[i] = bigchain.DefaultTxOwnerBefore(tx)
	}
	if signatures != nil {
		thresholdFulfillment, err := Threshold(recording, artistKeys, signatures)
		if err != nil {
			return nil, err
		}
		recording.Set("thresholdSignature", thresholdFulfillment.String())
	}
	if n == 1 {
		return api.SendIndividualCreateTx(100, recording, artistKeys[0])
	}
	return api.SendMultipleOwnersCreateTx(percentShares, recording, artistKeys)
}
