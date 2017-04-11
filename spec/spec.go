package spec

import (
	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/regex"
)

const CONTEXT = "CONTEXT"

func NewLink(id string) Data {
	return Data{"@id": id}
}

func GetId(data Data) string {
	return data.GetStr("@id")
}

func MatchId(id string) bool {
	return MatchStr(regex.ID, id)
}

func GetType(data Data) string {
	return data.GetStr("@type")
}

func NewUser(email, ipi, isni string, memberIds []string, name, pro, sameAs, _type string) (Data, error) {
	user := Data{
		"@context": CONTEXT,
		"@type":    _type,
		"name":     name,
	}
	switch _type {
	case "MusicGroup", "Organization":
		if n := len(memberIds); n > 0 {
			member := make([]Data, n)
			for i, memberId := range memberIds {
				if !MatchId(memberId) {
					return nil, Error("invalid member id")
				}
				member[i] = NewLink(memberId)
			}
			user.Set("member", member)
		}
	case "Person":
		//..
	default:
		return nil, ErrorAppend(ErrInvalidType, _type)
	}
	if MatchStr(regex.EMAIL, email) {
		user.Set("email", email)
	}
	if MatchStr(regex.IPI, ipi) {
		user.Set("ipiNumber", ipi)
	}
	if MatchStr(regex.ISNI, isni) {
		user.Set("isniNumber", isni)
	}
	if MatchStr(regex.PRO, pro) {
		user.Set("pro", pro)
	}
	if MatchUrlRelaxed(sameAs) {
		user.Set("sameAs", sameAs)
	}
	return user, nil
}

func GetDescription(data Data) string {
	return data.GetStr("description")
}

func GetEmail(data Data) string {
	return data.GetStr("email")
}

func GetIPI(data Data) string {
	return data.GetStr("ipiNumber")
}

func GetISNI(data Data) string {
	return data.GetStr("isniNumber")
}

func GetMemberIds(data Data) []string {
	members := data.GetDataSlice("member")
	memberIds := make([]string, len(members))
	for i, member := range members {
		memberIds[i] = GetId(member)
	}
	return memberIds
}

func GetName(data Data) string {
	return data.GetStr("name")
}

func GetPRO(data Data) string {
	return data.GetStr("pro")
}

func GetSameAs(data Data) string {
	return data.GetStr("sameAs")
}

func NewComposition(composerIds []string, inLanguage, iswcCode, name string, publisherIds []string, url string) (Data, error) {
	composition := Data{
		"@context": CONTEXT,
		"@type":    "MusicComposition",
		"name":     name,
	}
	n := len(composerIds)
	if n == 0 {
		return nil, Error("no composer ids")
	}
	composers := make([]Data, n)
	for i, composerId := range composerIds {
		if !MatchId(composerId) {
			return nil, Error("invalid composer id")
		}
		composers[i] = NewLink(composerId)
	}
	composition.Set("composer", composers)
	if m := len(publisherIds); m > 0 {
		publishers := make([]Data, m)
		for i, publisherId := range publisherIds {
			if !MatchId(publisherId) {
				return nil, Error("invalid publisher id")
			}
			publishers[i] = NewLink(publisherId)
		}
		composition.Set("publisher", publishers)
	}
	if MatchStr(regex.LANGUAGE, inLanguage) {
		composition.Set("inLanguage", inLanguage)
	}
	if MatchStr(regex.ISWC, iswcCode) {
		composition.Set("iswcCode", iswcCode)
	}
	if MatchUrlRelaxed(url) {
		composition.Set("url", url)
	}
	return composition, nil
}

func GetComposers(data Data) []Data {
	return AssertDataSlice(data.Get("composer"))
}

func GetLanguage(data Data) string {
	return data.GetStr("inLanguage")
}

func GetISWC(data Data) string {
	return data.GetStr("iswcCode")
}

func GetPublishers(data Data) []Data {
	return AssertDataSlice(data.Get("publisher"))
}

func NewRecording(artistIds []string, compositionId, duration, isrcCode string, licenseIds, recordLabelIds, rightIds []string, url string) (Data, error) {
	recording := Data{
		"@context":    CONTEXT,
		"@type":       "MusicRecording",
		"recordingOf": NewLink(compositionId),
	}
	n := len(artistIds)
	if n == 0 {
		return nil, Error("no artist ids")
	}
	m := len(recordLabelIds)
	if licenseIds != nil {
		if len(licenseIds) != n+m {
			return nil, Error("invalid number of artist/record label and license ids")
		}
	}
	if rightIds != nil {
		if len(rightIds) != n+m {
			return nil, Error("invalid number of artist/record label and right ids")
		}
	}
	artists := make([]Data, n)
	for i, artistId := range artistIds {
		if !MatchId(artistId) {
			return nil, Error("invalid artist id")
		}
		artists[i] = NewLink(artistId)
		if licenseIds != nil {
			if MatchId(licenseIds[i]) {
				artists[i].Set("hasLicense", NewLink(licenseIds[i]))
				continue
			}
		}
		if rightIds != nil {
			if MatchId(rightIds[i]) {
				artists[i].Set("hasRight", NewLink(rightIds[i]))
			}
		}
	}
	recording.Set("byArtist", artists)
	if m > 0 {
		recordLabels := make([]Data, m)
		for i, recordLabelId := range recordLabelIds {
			if !MatchId(recordLabelId) {
				return nil, Error("invalid record label id")
			}
			recordLabels[i] = NewLink(recordLabelId)
			if licenseIds != nil {
				if MatchId(licenseIds[n+i]) {
					recordLabels[i].Set("hasLicense", NewLink(licenseIds[n+i]))
					continue
				}
			}
			if rightIds != nil {
				if MatchId(rightIds[n+i]) {
					recordLabels[i].Set("hasRight", NewLink(rightIds[n+i]))
				}
			}
		}
		recording.Set("recordLabel", recordLabels)
	}
	if !EmptyStr(duration) {
		// TODO: match str duration
		recording.Set("duration", duration)
	}
	if MatchStr(regex.ISRC, isrcCode) {
		recording.Set("isrcCode", isrcCode)
	}
	if MatchUrlRelaxed(url) {
		recording.Set("url", url)
	}
	return recording, nil
}

func GetArtists(data Data) []Data {
	return AssertDataSlice(data.Get("byArtist"))
}

func GetDuration(data Data) string {
	return data.GetStr("duration")
}

func GetISRC(data Data) string {
	return data.GetStr("isrcCode")
}

func GetLicenseId(data Data) string {
	return GetId(data.GetData("hasLicense"))
}

func GetRecordingOfId(data Data) string {
	return GetId(data.GetData("recordingOf"))
}

func GetRecordLabels(data Data) []Data {
	return AssertDataSlice(data.Get("recordLabel"))
}

// Note: transferId is the hex id of a TRANSFER tx in BigchainDB/IPDB
// the output amount(s) will specify shares kept/transferred

func NewRight(rightHolderIds []string, rightTo, transferId string) (Data, error) {
	n := len(rightHolderIds)
	if n == 0 {
		return nil, Error("no right-holder ids")
	}
	rightHolders := make([]Data, n)
	for i, rightHolderId := range rightHolderIds {
		rightHolders[i] = NewLink(rightHolderId)
	}
	return Data{
		"@context":    CONTEXT,
		"@type":       "Right",
		"rightHolder": rightHolders,
		"rightTo":     NewLink(rightTo),
		"transfer":    NewLink(transferId),
	}, nil
}

func GetRightToId(data Data) string {
	composition := data.GetData("rightTo")
	return GetId(composition)
}

func GetRightHolderIds(data Data) []string {
	rightHolders := data.GetDataSlice("rightHolder")
	rightHolderIds := make([]string, len(rightHolders))
	for i, rightHolder := range rightHolders {
		rightHolderIds[i] = GetId(rightHolder)
	}
	return rightHolderIds
}

func GetTransferId(data Data) string {
	transfer := data.GetData("transfer")
	return GetId(transfer)
}

func NewLicense(licenseForIds, licenseHolderIds []string, licenserId string, rightIds []string, validFrom, validThrough string) (Data, error) {
	dateFrom, err := ParseDate(validFrom)
	if err != nil {
		return nil, err
	}
	// if dateFrom.Before(Today()) {
	//	return nil, Error("Invalid timeframe")
	// }
	dateThrough, err := ParseDate(validThrough)
	if err != nil {
		return nil, err
	}
	if !dateThrough.After(dateFrom) {
		return nil, Error("invalid license timeframe")
	}
	n := len(licenseForIds)
	if n == 0 {
		return nil, Error("no composition/recording ids")
	}
	if rightIds != nil {
		if len(rightIds) != n {
			return nil, Error("invalid number of composition/recording and right ids")
		}
	}
	licenseFor := make([]Data, n)
	rights := make([]Data, n)
	for i, licenseForId := range licenseForIds {
		if !MatchId(licenseForId) {
			return nil, ErrInvalidId
		}
		licenseFor[i] = NewLink(licenseForId)
		if rightIds != nil {
			if MatchId(rightIds[i]) {
				rights[i] = NewLink(rightIds[i])
			}
		}
	}
	n = len(licenseHolderIds)
	if n == 0 {
		return nil, Error("no license-holder ids")
	}
	licenseHolders := make([]Data, n)
	for i, licenseHolderId := range licenseHolderIds {
		if !MatchId(licenseHolderId) {
			return nil, ErrInvalidId
		}
		licenseHolders[i] = NewLink(licenseHolderId)
	}
	if !MatchId(licenserId) {
		return nil, ErrInvalidId
	}
	licenser := NewLink(licenserId)
	if rightIds != nil {
		licenser.Set("hasRight", rights)
	}
	return Data{
		"@context":      CONTEXT,
		"@type":         "License",
		"licenseFor":    licenseFor,
		"licenseHolder": licenseHolders,
		"licenser":      licenser,
		"validFrom":     validFrom,
		"validThrough":  validThrough,
	}, nil
}

func GetLicenseForIds(data Data) []string {
	licenseFor := data.GetDataSlice("licenseFor")
	licenseForIds := make([]string, len(licenseFor))
	for i := range licenseFor {
		licenseForIds[i] = GetId(licenseFor[i])
	}
	return licenseForIds
}

func GetLicenseHolderIds(data Data) []string {
	licenseHolders := data.GetDataSlice("licenseHolder")
	licenseHolderIds := make([]string, len(licenseHolders))
	for i, licenseHolder := range licenseHolders {
		licenseHolderIds[i] = GetId(licenseHolder)
	}
	return licenseHolderIds
}

func GetLicenser(data Data) Data {
	return data.GetData("licenser")
}

func GetRightId(data Data) string {
	return GetId(data.GetData("hasRight"))
}

func GetRightIds(data Data) []string {
	rights := data.GetDataSlice("hasRight")
	rightIds := make([]string, len(rights))
	for i, right := range rights {
		rightIds[i] = GetId(right)
	}
	return rightIds
}

func GetValidFrom(data Data) string {
	return data.GetStr("validFrom")
}

func GetValidThrough(data Data) string {
	return data.GetStr("validThrough")
}
