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
	mux.HandleFunc("/right_handler", api.RightHandler)
	mux.HandleFunc("/publish_handler", api.PublishHandler)
	mux.HandleFunc("/release_handler", api.ReleaseHandler)
	mux.HandleFunc("/license_handler", api.LicenseHandler)
	// mux.HandleFunc("/search_handler", api.SearchHandler)
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
	if err = api.Register(party, path); err != nil {
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
	var right Data
	recipientId := values.Get("recipientId")
	recipientShares := MustAtoi(values.Get("recipientShares"))
	senderId := values.Get("senderId")
	territory := SplitStr(values.Get("territory"), ",")
	_type := values.Get("type")
	uri := values.Get("uri")
	validFrom := values.Get("validFrom")
	validThrough := values.Get("validThrough")
	if _type == "composition_right" {
		right, err = api.Right(recipientShares, spec.NewCompositionRight(recipientId, senderId, territory, uri, validFrom, validThrough))
	} else if _type == "recording_right" {
		right, err = api.Right(recipientShares, spec.NewRecordingRight(recipientId, senderId, territory, uri, validFrom, validThrough))
	} else {
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, right)
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
	composerRoles := SplitStr(values.Get("composerRoles"), ",")
	hfa := values.Get("hfa")
	iswc := values.Get("iswc")
	lang := values.Get("lang")
	name := values.Get("name")
	publisherIds := SplitStr(values.Get("publisherIds"), ",")
	composerRoles := SplitStr(values.Get("composerRoles"), ",")
	sameAs := values.Get("sameAs")
	composition, err := api.DefaultSendIndividualCreateTx(spec.NewComposition(collaboration, composerId, hfa, iswc, lang, publisherId, sameAs, title, uri))
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
	artistId := form.Value["artistId"][0]
	collaboration := form.Value["collaboration"][0] == "true"
	compositionId := form.Value["compositionId"][0]
	compositionRightId := form.Value["compositionRightId"][0]
	duration := form.Value["duration"][0]
	file, err := form.File["recording"][0].Open()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	isrc := form.Value["isrc"][0]
	mechanicalLicenseId := form.Value["mechanicalLicenseId"][0]
	publicationId := form.Value["publicationId"][0]
	recordLabelId := form.Value["recordLabelId"][0]
	sameAs := form.Value["sameAs"][0]
	uri := form.Value["uri"][0]
	recording, err = api.Record(file, spec.NewRecording(artistId, collaboration, compositionId, compositionRightId, duration, isrc, mechanicalLicenseId, publicationId, recordLabelId, sameAs, uri))
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
	compositionRightIds := SplitStr(values.Get("compositionRightIds"), ",")
	publisherId := values.Get("publisherId")
	sameAs := values.Get("sameAs")
	title := values.Get("title")
	publication, err := api.SendTxPublication(spec.NewPublication(compositionsId, compositionRightIds, publisherId, sameAs, title))
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
	recordingIds := SplitStr(values.Get("recordingIds"), ",")
	recordingRightIds := SplitStr(values.Get("recordingRightIds"), ",")
	recordLabelId := values.Get("recordLabelId")
	sameAs := values.Get("sameAs")
	title := values.Get("title")
	release, err := api.SendTxRelease(spec.NewRelease(title, recordingIds, recordingRightIds, recordLabelId, sameAs))
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
	var license Data
	recipientId := values.Get("recipientId")
	rightId := values.Get("rightId")
	senderId := values.Get("senderId")
	territory := SplitStr(values.Get("territory"), ",")
	transferId := values.Get("transferId")
	_type := values.Get("type")
	usage := SplitStr(values.Get("usage"), ",")
	validFrom := values.Get("validFrom")
	validThrough := values.Get("validThrough")
	if _type == "mechanical_license" {
		compositionIds := SplitStr(values.Get("compositionIds"), ",")
		publicationId := values.Get("publicationId")
		license, err = api.SendTxLicense(spec.NewMechanicalLicense(compositionIds, rightId, transferId, publicationId, recipientId, senderId, territory, usage, validFrom, validThrough))
	} else if _type == "master_license" {
		recordingIds := SplitStr(values.Get("recordingIds"), ",")
		releaseId := values.Get("releaseId")
		license, err = api.SendTxLicense(spec.NewMasterLicense(recipientId, recordingIds, rightId, senderId, transferId, releaseId, territory, usage, validFrom, validThrough))
	} else {
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
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
		compositionId := values.Get("compositionId")
		sig, err = ld.ProveComposer(challenge, compositionId, api.priv)
	case "composition_right":
		rightId := values.Get("rightId")
		publicationId := values.Get("publicationReleaseId")
		sig, err = ld.ProveCompositionRightHolder(challenge, rightId, api.priv, publicationId)
	case "composition_right_transfer":
		transferId := values.Get("transferId")
		publicationId := values.Get("publicationReleaseId")
		sig, err = ld.ProveCompositionRightTransferHolder(challenge, transferId, api.partyId, api.priv, publicationId)
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
		recordingId := values.Get("recordingId")
		sig, err = ld.ProvePerformer(challenge, api.priv, recordingId)
	case "recording_right":
		rightId := values.Get("rightId")
		releaseId := values.Get("publicationReleaseId")
		sig, err = ld.ProveRecordingRightHolder(challenge, api.priv, rightId, releaseId)
	case "recording_right_transfer":
		transferId := values.Get("transferId")
		releaseId := values.Get("publicationReleaseId")
		sig, err = ld.ProveRecordingRightTransferHolder(challenge, api.partyId, api.priv, transferId, releaseId)
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
		compositionId := values.Get("compositionId")
		err = ld.VerifyComposer(challenge, compositionId, sig)
	case "composition_right":
		rightId := values.Get("rightId")
		publicationId := values.Get("publicationReleaseId")
		err = ld.VerifyCompositionRightHolder(challenge, rightId, publicationId, sig)
	case "composition_right_transfer":
		transferId := values.Get("transferId")
		publicationId := values.Get("publicationReleaseId")
		err = ld.VerifyCompositionRightTransferHolder(challenge, transferId, api.partyId, publicationId, sig)
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
		recordingId := values.Get("recordingId")
		err = ld.VerifyPerformer(challenge, recordingId, sig)
	case "recording_right":
		rightId := values.Get("rightId")
		releaseId := values.Get("publicationReleaseId")
		err = ld.VerifyRecordingRightHolder(challenge, rightId, releaseId, sig)
	case "recording_right_transfer":
		transferId := values.Get("transferId")
		releaseId := values.Get("publicationReleaseId")
		err = ld.VerifyRecordingRightTransferHolder(challenge, api.partyId, transferId, releaseId, sig)
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
	var model interface{}
	field := values.Get("field")
	_type := values.Get("type")
	switch _type {
	case "composition":
		compositionId := values.Get("compositionId")
		model, err = ld.QueryCompositionField(compositionId, field)
	case "master_license":
		licenseId := values.Get("licenseId")
		model, err = ld.QueryMasterLicenseField(field, licenseId)
	case "mechanical_license":
		licenseId := values.Get("licenseId")
		model, err = ld.QueryMechanicalLicenseField(field, licenseId)
	case "publication":
		publicationId := values.Get("publicationId")
		model, err = ld.QueryPublicationField(field, publicationId)
	case "recording":
		recordingId := values.Get("recordingId")
		model, err = ld.QueryRecordingField(field, recordingId)
	case "release":
		releaseId := values.Get("releaseId")
		model, err = ld.QueryReleaseField(field, releaseId)
	default:
		http.Error(w, "Expected publicationId or releaseId", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, model)
}

func (api *Api) TransferHandler(w http.ResponseWriter, req *http.Request) {
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
	var transfer Data
	recipientId := values.Get("recipientId")
	recipientShares := MustAtoi(values.Get("recipientShares"))
	rightId := values.Get("rightId")
	transferId := values.Get("transferId")
	_type := values.Get("type")
	switch _type {
	case "composition_right_transfer":
		publicationId := values.Get("publicationReleaseId")
		transfer, err = api.TransferCompositionRight(rightId, transferId, publicationId, recipientId, recipientShares)
	case "recording_right_transfer":
		releaseId := values.Get("publicationReleaseId")
		transfer, err = api.TransferRecordingRight(recipientId, recipientShares, rightId, transferId, releaseId)
	default:
		http.Error(w, ErrorAppend(ErrInvalidType, _type).Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	WriteJSON(w, transfer)
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

func (api *Api) Login(id, privstr string) error {
	priv := new(ed25519.PrivateKey)
	if err := priv.FromString(privstr); err != nil {
		return err
	}
	tx, err := ld.QueryAndValidateModel(id, "party")
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

func (api *Api) Register(party Data, path string) error {
	file, err := CreateFile(path + "/credentials.json")
	if err != nil {
		return err
	}
	api.priv, api.pub = ed25519.GenerateKeypairFromPassword(password)
	credentials, err := api.DefaultSendIndividualCreateTx(party)
	if err != nil {
		return err
	}
	api.priv, api.pub = nil, nil
	WriteJSON(file, credentials)
	return nil
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
	tx := bigchain.DefaultMultipleOwnersCreateTx(amounts, data, ownersAfter, api.pub)
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

func (api *Api) Collaborate(collab Data, memberIds []string) (Data, error) {
	owners := make([]crypto.PublicKey, len(memberIds))
	for i, memberId := range memberIds {
		tx, err := ld.QueryAndValidateModel(memberId, "party")
		if err != nil {
			return nil, err
		}
		owners[i] = bigchain.DefaultGetTxSender(tx)
	}
	return api.DefaultSendMultipleOwnersCreateTx(collab, owners)
}

func (api *Api) Record(file io.Reader, recording Data) (Data, error) {
	// rs := MustReadSeeker(file)
	// meta, err := tag.ReadFrom(rs)
	// if err != nil {
	//	return nil, err
	// }
	// metadata := meta.Raw()
	if spec.IsCollaboration(recording) {
		tx, err := ld.QueryAndValidateModel(spec.GetArtistId(recording), "collaboration")
		if err != nil {
			return nil, err
		}
		collab := bigchain.GetTxData(tx)

		return api.DefaultSendMultipleOwnersCreateTx(recording, owners)
	}
	return api.DefaultSendIndividualCreateTx(recording)
}

func (api *Api) Right(recipientShares int, right Data) (Data, error) {
	tx, err := bigchain.GetTx(spec.GetRecipientId(right))
	if err != nil {
		return nil, err
	}
	recipientPub := bigchain.DefaultGetTxSender(tx)
	return api.SendIndividualCreateTx(recipientShares, data, recipientPub)
}

// Note: output 0 for sender shares and output 1 for recipient shares

func (api *Api) TransferCompositionRight(compositionRightId, compositionRightTransferId, publicationId, recipientId string, recipientShares int) (Data, error) {
	var output, totalShares int
	var txId string
	if !EmptyStr(compositionRightTransferId) {
		compositionRightTransfer, err := ld.ValidateCompositionRightTransfer(compositionRightTransferId)
		if err != nil {
			return nil, err
		}
		if api.partyId == spec.GetRecipientId(compositionRightTransfer) {
			totalShares = spec.GetRecipientShares(compositionRightTransfer)
			output = 1
		} else if api.partyId == spec.GetSenderId(compositionRightTransfer) {
			totalShares = spec.GetSenderShares(compositionRightTransfer)
		} else {
			return nil, ErrorAppend(ErrCriteriaNotMet, "partyId does not match recipientId or senderId of TRANSFER tx")
		}
		compositionRightId = spec.GetCompositionRightId(compositionRightTransfer)
		txId = spec.GetTxId(compositionRightTransfer)
	} else {
		tx, err := bigchain.GetTx(compositionRightId)
		if err != nil {
			return nil, err
		}
		totalShares = bigchain.GetTxShares(tx)
		txId = compositionRightId
	}
	tx, err := bigchain.GetTx(recipientId)
	if err != nil {
		return nil, err
	}
	recipientPub := bigchain.DefaultGetTxSender(tx)
	senderShares := totalShares - recipientShares
	if senderShares < 0 {
		return nil, ErrorAppend(ErrCriteriaNotMet, "cannot transfer this many shares")
	}
	if senderShares == 0 {
		tx = bigchain.IndividualTransferTx(recipientShares, compositionRightId, txId, output, recipientPub, api.pub)
	} else {
		tx = bigchain.DivisibleTransferTx([]int{senderShares, recipientShares}, compositionRightId, txId, output, []crypto.PublicKey{api.pub, recipientPub}, api.pub)
	}
	bigchain.FulfillTx(tx, api.priv)
	txId, err = bigchain.PostTx(tx)
	if err != nil {
		return nil, err
	}
	compositionRightTransfer := spec.NewCompositionRightTransfer(compositionRightId, publicationId, recipientId, api.partyId, txId)
	tx = bigchain.DefaultIndividualCreateTx(compositionRightTransfer, api.pub)
	bigchain.FulfillTx(tx, api.priv)
	id, err := bigchain.PostTx(tx)
	if err != nil {
		return nil, err
	}
	api.logger.Info("SUCCESS sent tx with composition right transfer")
	return Data{
		"compositionRightTransfer": compositionRightTransfer,
		"id": id,
	}, nil
}

func (api *Api) TransferRecordingRight(recipientId string, recipientShares int, recordingRightId, recordingRightTransferId, releaseId string) (Data, error) {
	var output, totalShares int
	var txId string
	if !EmptyStr(recordingRightTransferId) {
		recordingRightTransfer, err := ld.ValidateRecordingRightTransfer(recordingRightTransferId)
		if err != nil {
			return nil, err
		}
		if api.partyId == spec.GetRecipientId(recordingRightTransfer) {
			totalShares = spec.GetRecipientShares(recordingRightTransfer)
			output = 1
		} else if api.partyId == spec.GetSenderId(recordingRightTransfer) {
			totalShares = spec.GetSenderShares(recordingRightTransfer)
		} else {
			return nil, ErrorAppend(ErrCriteriaNotMet, "partyId does not match recipientId or senderId of TRANSFER tx")
		}
		recordingRightId = spec.GetRecordingRightId(recordingRightTransfer)
		txId = spec.GetTxId(recordingRightTransfer)
	} else {
		tx, err := bigchain.GetTx(recordingRightId)
		if err != nil {
			return nil, err
		}
		totalShares = bigchain.GetTxShares(tx)
		txId = recordingRightId
	}
	tx, err := bigchain.GetTx(recipientId)
	if err != nil {
		return nil, err
	}
	recipientPub := bigchain.DefaultGetTxSender(tx)
	senderShares := totalShares - recipientShares
	if senderShares < 0 {
		return nil, ErrorAppend(ErrCriteriaNotMet, "cannot transfer this many shares")
	}
	if senderShares == 0 {
		tx = bigchain.IndividualTransferTx(recipientShares, recordingRightId, txId, output, recipientPub, api.pub)
	} else {
		tx = bigchain.DivisibleTransferTx([]int{senderShares, recipientShares}, recordingRightId, txId, output, []crypto.PublicKey{api.pub, recipientPub}, api.pub)
	}
	bigchain.FulfillTx(tx, api.priv)
	txId, err = bigchain.PostTx(tx)
	if err != nil {
		return nil, err
	}
	recordingRightTransfer := spec.NewRecordingRightTransfer(recipientId, recordingRightId, releaseId, api.partyId, txId)
	tx = bigchain.DefaultIndividualCreateTx(recordingRightTransfer, api.pub)
	bigchain.FulfillTx(tx, api.priv)
	id, err := bigchain.PostTx(tx)
	if err != nil {
		return nil, err
	}
	api.logger.Info("SUCCESS sent tx with recording right transfer")
	return Data{
		"id": id,
		"recordingRightTransfer": recordingRightTransfer,
	}, nil
}
