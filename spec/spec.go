package spec

import (
	. "github.com/zbo14/envoke/common"
	regex "github.com/zbo14/envoke/regex"
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

func NewParty(email, ipi, isni string, memberIds []string, name, pro, sameAs, _type string) Data {
	party := Data{
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
			party.Set("member", member)
		}
	case "Person":
		//..
	default:
		panic(ErrorAppend(ErrInvalidType, _type))
	}
	if MatchStr(regex.EMAIL, email) {
		party.Set("email", email)
	}
	if MatchStr(regex.IPI, ipi) {
		party.Set("ipiNumber", ipi)
	}
	if MatchStr(regex.ISNI, isni) {
		party.Set("isniNumber", isni)
	}
	if MatchStr(regex.PRO, pro) {
		party.Set("pro", pro)
	}
	if MatchUrlRelaxed(sameAs) {
		party.Set("sameAs", sameAs)
	}
	return party
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

func NewComposition(composerIds []string, hfa, iswc, lang, name string, roles []string, sameAs, uri string) Data {
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
		if roles != nil {
			if n != len(roles) {
				panic("Number of roles doesn't equal number of composers")
			}
		}
		composers := make([]Data, n)
		for i, composerId := range composerIds {
			composers[i] = NewLink(composerId)
			if roles != nil {
				composers[i].Set("role", roles[i])
			}
		}
		composition.Set("composer", composers)
	}
	if MatchStr(regex.HFA, hfa) {
		composition.Set("hfaCode", hfa)
	}
	if MatchStr(regex.ISWC, iswc) {
		composition.Set("iswcCode", iswc)
	}
	if MatchStr(regex.LANGUAGE, lang) {
		composition.Set("inLanguage", lang)
	}
	if MatchUrlRelaxed(sameAs) {
		composition.Set("sameAs", sameAs)
	}
	if MatchStr(regex.FULFILLMENT, uri) {
		composition.Set("uri", uri)
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

func GetURI(data Data) string {
	return data.GetStr("uri")
}

func NewPublication(compositionIds []string, name, publisherId string, rightIds []string, sameAs string) Data {
	publication := Data{
		"@context":  CONTEXT,
		"@type":     "MusicPublication",
		"name":      name,
		"publisher": NewLink(publisherId),
	}
	if n, m := len(compositionIds), len(rightIds); n == 0 {
		panic("No compositionIds")
	} else if n == 1 && m == 1 {
		publication.Set("composition", Data{
			"@id":   compositionIds[0],
			"right": NewLink(rightIds[0]),
		})
	} else if n == m {
		compositions := make([]Data, n)
		for i := range compositions {
			compositions[i] = Data{
				"@id":   compositionIds[i],
				"right": NewLink(rightIds[i]),
			}
		}
		publication.Set("composition", compositions)
	} else {
		panic("Invalid number of compositionIds/rightIds")
	}
	if MatchUrlRelaxed(sameAs) {
		publication.Set("sameAs", sameAs)
	}
	return publication
}

func GetCompositions(data Data) []Data {
	v := data.Get("composition")
	if composition := AssertData(v); composition != nil {
		return []Data{composition}
	}
	return AssertDataSlice(v)
}

func GetPublisherId(data Data) string {
	publisher := data.GetData("publisher")
	return GetId(publisher)
}

func GetRightId(data Data) string {
	right := data.GetData("right")
	return GetId(right)
}

func NewRecording(artistIds []string, compositionId, duration, isrc string, mechanicalLicenseIds, roles []string, sameAs, uri string) Data {
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
		if n != len(mechanicalLicenseIds) {
			panic("Number of mechanicalLicenseIds doesn't equal number of artists")
		}
		if roles != nil {
			if n != len(roles) {
				panic("Number of roles doesn't equal number of artists")
			}
		}
		artists := make([]Data, n)
		for i, artistId := range artistIds {
			artists[i] = NewLink(artistId)
			if MatchId(mechanicalLicenseIds[i]) {
				artists[i].Set("mechanicalLicense", NewLink(mechanicalLicenseIds[i]))
			}
			if roles != nil {
				artists[i].Set("role", roles[i])
			}
		}
		recording.Set("byArtist", artists)
	}
	if !EmptyStr(duration) {
		recording.Set("duration", duration)
	}
	if MatchStr(regex.ISRC, isrc) {
		recording.Set("isrcCode", isrc)
	}
	if MatchUrlRelaxed(sameAs) {
		recording.Set("sameAs", sameAs)
	}
	if MatchStr(regex.FULFILLMENT, uri) {
		recording.Set("uri", uri)
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
	return data.GetStr("isrc")
}

func GetMechanicalLicenseId(data Data) string {
	mechanical := data.GetData("mechanicalLicense")
	return GetId(mechanical)
}

func GetRecordingOfId(data Data) string {
	composition := data.GetData("recordingOf")
	return GetId(composition)
}

func NewRelease(name string, recordingIds []string, recordLabelId string, rightIds []string, sameAs string) Data {
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
			"@id":   recordingIds[0],
			"right": NewLink(rightIds[0]),
		})
	} else if n == m {
		recordings := make([]Data, n)
		for i := range recordings {
			recordings[i] = Data{
				"@id":   recordingIds[i],
				"right": NewLink(rightIds[i]),
			}
		}
		release.Set("recording", recordings)
	} else {
		panic("Invalid number of recordingIds/rightIds")
	}
	if MatchUrlRelaxed(sameAs) {
		release.Set("sameAs", sameAs)
	}
	return release
}

func GetRecordings(data Data) []Data {
	v := data.Get("recordings")
	if recording := AssertData(v); recording != nil {
		return []Data{recording}
	}
	return AssertDataSlice(v)
}

func GetRecordLabelId(data Data) string {
	recordLabel := data.GetData("recordLabel")
	return GetId(recordLabel)
}

// Note: transferId is the hex id of a TRANSFER tx in BigchainDB/IPDB
// the output amount(s) will specify shares transferred/kept

func NewCompositionRight(compositionId string, rightHolderIds []string, transferId string) Data {
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
		"@type":       "CompositionRight",
		"composition": NewLink(compositionId),
		"rightHolder": rightHolders,
		"transfer":    NewLink(transferId),
	}
}

func GetCompositionId(data Data) string {
	composition := data.GetData("composition")
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

func NewRecordingRight(recordingId string, rightHolderIds []string, transferId string) Data {
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
		"@type":       "RecordingRight",
		"recording":   NewLink(recordingId),
		"rightHolder": rightHolders,
		"transfer":    NewLink(transferId),
	}
}

func GetRecordingId(data Data) string {
	recording := data.GetData("recording")
	return GetId(recording)
}

func NewMechanicalLicense(compositionIds []string, licenseeId, licenserId string, rightIds []string, validFrom, validThrough string) Data {
	mechanicalLicense := Data{
		"@context":     CONTEXT,
		"@type":        "MechanicalLicense",
		"licensee":     NewLink(licenseeId),
		"licenser":     NewLink(licenserId),
		"validFrom":    validFrom,
		"validThrough": validThrough,
	}
	if n, m := len(compositionIds), len(rightIds); n == 0 {
		panic("No compositionIds")
	} else if n == m || m == 0 {
		compositions := make([]Data, n)
		for i, compositionId := range compositionIds {
			if !MatchId(compositionId) {
				panic(ErrorAppend(ErrInvalidId, compositionId))
			}
			compositions[i] = NewLink(compositionId)
			if m > 0 {
				if MatchId(rightIds[i]) {
					compositions[i].Set("right", NewLink(rightIds[i]))
				}
			}
		}
		mechanicalLicense.Set("composition", compositions)
	} else {
		panic("Invalid number of compositionIds/rightIds")
	}
	return mechanicalLicense
}

func GetLicenseeId(data Data) string {
	licensee := data.GetData("licensee")
	return GetId(licensee)
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

func NewMasterLicense(licenseeId, licenserId string, recordingIds, rightIds []string, validFrom, validThrough string) Data {
	masterLicense := Data{
		"@context":     CONTEXT,
		"@type":        "MasterLicense",
		"licensee":     NewLink(licenseeId),
		"licenser":     NewLink(licenserId),
		"validFrom":    validFrom,
		"validThrough": validThrough,
	}
	if n, m := len(recordingIds), len(rightIds); n == 0 {
		panic("No recordingIds")
	} else if n == m || m == 0 {
		recordings := make([]Data, n)
		for i, recordingId := range recordingIds {
			if !MatchId(recordingId) {
				panic(ErrorAppend(ErrInvalidId, recordingId))
			}
			recordings[i] = NewLink(recordingId)
			if m > 0 {
				if MatchId(rightIds[i]) {
					recordings[i].Set("right", NewLink(rightIds[i]))
				}
			}
		}
		masterLicense.Set("recording", recordings)
	} else {
		panic("Invalid number of recordingIds/rightIds")
	}
	return masterLicense
}
