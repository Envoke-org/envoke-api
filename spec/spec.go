package spec

import (
	. "github.com/zbo14/envoke/common"
	"github.com/zbo14/envoke/regex"
)

const CONTEXT = "http://localhost:8888/spec#Context"

func NewLink(id string) Data {
	return Data{"@id": id}
}

func GetId(data Data) string {
	return data.GetStr("@id")
}

func SetId(data Data, id string) {
	data.Set("@id", id)
}

func MatchId(id string) bool {
	return MatchStr(regex.ID, id)
}

func GetType(data Data) string {
	return data.GetStr("@type")
}

func NewUser(email, ipi, isni string, memberIds []string, name, pro, sameAs, _type string) Data {
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
					panic("Invalid memberId")
				}
				member[i] = NewLink(memberId)
			}
			user.Set("member", member)
		}
	case "Person":
		//..
	default:
		panic(ErrorAppend(ErrInvalidType, _type))
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
	return user
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

func NewComposition(composerIds []string, hfaCode, inLanguage, iswcCode, name, publisherId string, thresholdSignature, url string) Data {
	composition := Data{
		"@context": CONTEXT,
		"@type":    "MusicComposition",
		"name":     name,
	}
	if n := len(composerIds); n == 0 {
		panic("No composers")
	} else if n == 1 {
		composition.Set("composer", NewLink(composerIds[0]))
	} else {
		composers := make([]Data, n)
		for i, composerId := range composerIds {
			composers[i] = NewLink(composerId)
		}
		composition.Set("composer", composers)
	}
	if MatchStr(regex.HFA, hfaCode) {
		composition.Set("hfaCode", hfaCode)
	}
	if MatchStr(regex.ISWC, iswcCode) {
		composition.Set("iswcCode", iswcCode)
	}
	if MatchStr(regex.LANGUAGE, inLanguage) {
		composition.Set("inLanguage", inLanguage)
	}
	if MatchId(publisherId) {
		composition.Set("publisher", NewLink(publisherId))
	}
	if MatchStr(regex.FULFILLMENT, thresholdSignature) {
		composition.Set("thresholdSignature", thresholdSignature)
	}
	if MatchUrlRelaxed(url) {
		composition.Set("url", url)
	}
	return composition
}

func GetComposers(data Data) []Data {
	v := data.Get("composer")
	if composer := AssertData(v); composer != nil {
		return []Data{composer}
	}
	return AssertDataSlice(v)
}

func GetHFA(data Data) string {
	return data.GetStr("hfaCode")
}

func GetISWC(data Data) string {
	return data.GetStr("iswcCode")
}

func GetLanguage(data Data) string {
	return data.GetStr("inLanguage")
}

func GetThresholdSignature(data Data) string {
	return data.GetStr("thresholdSignature")
}

func GetPublisherId(data Data) string {
	publisher := data.GetData("publisher")
	return GetId(publisher)
}

func NewRecording(artistIds []string, compositionId, duration, isrcCode, licenseId string, recordLabelId string, thresholdSignature, url string) Data {
	recording := Data{
		"@context":    CONTEXT,
		"@type":       "MusicRecording",
		"recordingOf": NewLink(compositionId),
	}
	if n := len(artistIds); n == 0 {
		panic("No artists")
	} else if n == 1 {
		recording.Set("byArtist", NewLink(artistIds[0]))
	} else {
		artists := make([]Data, n)
		for i, artistId := range artistIds {
			artists[i] = NewLink(artistId)
		}
		recording.Set("byArtist", artists)
	}
	if !EmptyStr(duration) {
		recording.Set("duration", duration)
	}
	if MatchStr(regex.ISRC, isrcCode) {
		recording.Set("isrcCode", isrcCode)
	}
	if MatchId(licenseId) {
		recording.GetData("recordingOf").Set("hasLicense", NewLink(licenseId))
	}
	if MatchId(recordLabelId) {
		recording.Set("recordLabel", NewLink(recordLabelId))
	}
	if MatchStr(regex.FULFILLMENT, thresholdSignature) {
		recording.Set("thresholdSignature", thresholdSignature)
	}
	if MatchUrlRelaxed(url) {
		recording.Set("url", url)
	}
	return recording
}

func GetArtists(data Data) []Data {
	v := data.Get("byArtist")
	if artist := AssertData(v); artist != nil {
		return []Data{artist}
	}
	return AssertDataSlice(v)
}

func GetDuration(data Data) string {
	return data.GetStr("duration")
}

func GetISRC(data Data) string {
	return data.GetStr("isrcCode")
}

func GetLicenseId(data Data) string {
	license := data.GetData("hasLicense")
	return GetId(license)
}

func GetRecordingOf(data Data) Data {
	return data.GetData("recordingOf")
}

func GetRecordLabelId(data Data) string {
	recordLabel := data.GetData("recordLabel")
	return GetId(recordLabel)
}

// TODO: addition release fields

func NewRelease(name string, recordingIds []string, recordLabelId string, rightIds []string, url string) Data {
	release := Data{
		"@context":    CONTEXT,
		"@type":       "MusicRelease",
		"name":        name,
		"recordLabel": NewLink(recordLabelId),
	}
	if n, m := len(recordingIds), len(rightIds); n == 0 {
		panic("No recordingIds")
	} else if n == 1 && m == 1 {
		release.Set("recording", Data{
			"@id":      recordingIds[0],
			"hasRight": NewLink(rightIds[0]),
		})
	} else if n == m {
		recordings := make([]Data, n)
		for i := range recordings {
			recordings[i] = Data{
				"@id":      recordingIds[i],
				"hasRight": NewLink(rightIds[i]),
			}
		}
		release.Set("recording", recordings)
	} else {
		panic("Invalid number of recordingIds/rightIds")
	}
	if MatchUrlRelaxed(url) {
		release.Set("url", url)
	}
	return release
}

func GetRightId(data Data) string {
	right := data.GetData("hasRight")
	return GetId(right)
}

func GetRecordings(data Data) []Data {
	v := data.Get("recordings")
	if recording := AssertData(v); recording != nil {
		return []Data{recording}
	}
	return AssertDataSlice(v)
}

// Note: transferId is the hex id of a TRANSFER tx in BigchainDB/IPDB
// the output amount(s) will specify shares kept/transferred

func NewRight(rightHolderIds []string, rightTo, transferId string) Data {
	n := len(rightHolderIds)
	if n == 0 {
		panic("No rightHolderIds")
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
	}
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

func NewLicense(licenseForIds, licenseHolderIds []string, licenserId string, rightIds []string, validFrom, validThrough string) Data {
	n := len(licenseHolderIds)
	if n == 0 {
		panic("No licenseHolderIds")
	}
	licenseHolders := make([]Data, n)
	for i, licenseHolderId := range licenseHolderIds {
		licenseHolders[i] = NewLink(licenseHolderId)
	}
	license := Data{
		"@context":      CONTEXT,
		"@type":         "License",
		"licenseHolder": licenseHolders,
		"licenser":      NewLink(licenserId),
		"validFrom":     validFrom,
		"validThrough":  validThrough,
	}
	if n, m := len(licenseForIds), len(rightIds); n == 0 {
		panic("No licenseForIds")
	} else if n == m || m == 0 {
		licenseFor := make([]Data, n)
		for i, licenseForId := range licenseForIds {
			if !MatchId(licenseForId) {
				panic(ErrorAppend(ErrInvalidId, licenseForId))
			}
			licenseFor[i] = NewLink(licenseForId)
			if m > 0 {
				if MatchId(rightIds[i]) {
					licenseFor[i].Set("hasRight", NewLink(rightIds[i]))
				}
			}
		}
		license.Set("licenseFor", licenseFor)
	} else {
		panic("Invalid number of licenseForIds/rightIds")
	}
	return license
}

func GetLicenseFor(data Data) []Data {
	return data.GetDataSlice("licenseFor")
}

func GetLicenseHolderIds(data Data) []string {
	licenseHolders := data.GetDataSlice("licenseHolder")
	licenseHolderIds := make([]string, len(licenseHolders))
	for i, licenseHolder := range licenseHolders {
		licenseHolderIds[i] = GetId(licenseHolder)
	}
	return licenseHolderIds
}

func GetLicenserId(data Data) string {
	licenser := data.GetData("licenser")
	return GetId(licenser)
}

func GetValidFrom(data Data) string {
	return data.GetStr("validFrom")
}

func GetValidTo(data Data) string {
	return data.GetStr("validTo")
}
