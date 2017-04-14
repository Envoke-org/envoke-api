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

func NewUser(email, isni string, memberIds []string, name, sameAs, _type string) (Data, error) {
	user := Data{
		"@context": CONTEXT,
		"@type":    _type,
		"name":     name,
	}
	switch _type {
	case "MusicGroup", "Organization":
		if len(memberIds) > 0 {
			member := make([]Data, len(memberIds))
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
	if MatchStr(regex.ISNI, isni) {
		user.Set("isniNumber", isni)
	}
	if MatchUrlRelaxed(sameAs) {
		user.Set("sameAs", sameAs)
	}
	return user, nil
}

func GetEmail(data Data) string {
	return data.GetStr("email")
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

func GetSameAs(data Data) string {
	return data.GetStr("sameAs")
}

func NewComposition(composerIds []string, inLanguage, iswcCode, name string, publisherIds []string, url string) (Data, error) {
	composition := Data{
		"@context": CONTEXT,
		"@type":    "MusicComposition",
		"name":     name,
	}
	if len(composerIds) == 0 {
		return nil, Error("no composer ids")
	}
	composers := make([]Data, len(composerIds))
	for i, composerId := range composerIds {
		if !MatchId(composerId) {
			return nil, Error("invalid composer id")
		}
		composers[i] = NewLink(composerId)
	}
	composition.Set("composer", composers)
	if len(publisherIds) > 0 {
		publishers := make([]Data, len(publisherIds))
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

func NewRecording(artistIds []string, compositionId, duration, isrcCode string, licenseIds, recordLabelIds []string, url string) (Data, error) {
	recording := Data{
		"@context":    CONTEXT,
		"@type":       "MusicRecording",
		"recordingOf": NewLink(compositionId),
	}
	if len(artistIds) == 0 {
		return nil, Error("no artist ids")
	}
	if licenseIds != nil {
		if len(licenseIds) != len(artistIds)+len(recordLabelIds) {
			return nil, Error("different number of artist/record label and license ids")
		}
	}
	artists := make([]Data, len(artistIds))
	for i, artistId := range artistIds {
		if !MatchId(artistId) {
			return nil, Error("invalid artist id")
		}
		artists[i] = NewLink(artistId)
		if licenseIds != nil {
			if MatchId(licenseIds[i]) {
				artists[i].Set("hasLicense", NewLink(licenseIds[i]))
			}
		}
	}
	recording.Set("byArtist", artists)
	if len(recordLabelIds) > 0 {
		recordLabels := make([]Data, len(recordLabelIds))
		for i, recordLabelId := range recordLabelIds {
			if !MatchId(recordLabelId) {
				return nil, Error("invalid record label id")
			}
			recordLabels[i] = NewLink(recordLabelId)
			if licenseIds != nil {
				if MatchId(licenseIds[len(artistIds)+i]) {
					recordLabels[i].Set("hasLicense", NewLink(licenseIds[len(artistIds)+i]))
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

func NewLicense(assetIds []string) (Data, error) {
	if len(assetIds) == 0 {
		return nil, Error("no asset ids")
	}
	asset := make([]Data, len(assetIds))
	for i, assetId := range assetIds {
		if !MatchId(assetId) {
			return nil, ErrInvalidId
		}
		asset[i] = NewLink(assetId)
	}
	return Data{
		"@context": CONTEXT,
		"@type":    "License",
		"asset":    asset,
	}, nil
}

func GetAssetIds(data Data) []string {
	asset := data.GetDataSlice("asset")
	assetIds := make([]string, len(asset))
	for i := range asset {
		assetIds[i] = GetId(asset[i])
	}
	return assetIds
}

func GetTimeout(data Data) string {
	return data.GetStr("timeout")
}
