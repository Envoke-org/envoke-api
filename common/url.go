package common

import (
	"github.com/mvdan/xurls"
	"net/url"
)

func MatchUrlStrict(rawurl string) bool {
	return xurls.Strict.MatchString(rawurl)
}

func MatchUrlRelaxed(rawurl string) bool {
	return xurls.Relaxed.MatchString(rawurl)
}

func ParseUrl(rawurl string) (*url.URL, error) {
	return url.Parse(rawurl)
}

func MustParseUrl(rawurl string) *url.URL {
	u, err := ParseUrl(rawurl)
	Check(err)
	return u
}

func ParseQuery(query string) (url.Values, error) {
	return url.ParseQuery(query)
}

func MustParseQuery(query string) url.Values {
	values, err := ParseQuery(query)
	Check(err)
	return values
}
