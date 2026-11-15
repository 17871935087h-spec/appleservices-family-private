package gsa

import (
	"fmt"
	"github.com/Laky-64/appleservices/internal/httpx"
	"maps"
	"net/http"
	"net/url"
)

type CookieKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Session struct {
	AnisetteHeaders map[string]string     `json:"anisetteHeaders"`
	Cookies         map[string][]CookieKV `json:"cookies"`
	DSID            string                `json:"dsid"`
	Tokens          map[string]string     `json:"tokens"`
}

func (c *Client) requestURLs() []string {
	return []string{
		gsaBaseURL + "/auth",
		gsaBaseURL + "/grandslam/GsService2",
		gsaBaseURL + "/auth/verify/trusteddevice",
		gsaBaseURL + "/grandslam/GsService2/validate",
		gsaBaseURL + "/auth/verify/phone",
		gsaBaseURL + "/auth/verify/phone/securitycode",
		deviceListURL,
		deviceServiceURL,
		deviceTeardownURL,
		circleServiceURL,
	}
}

func (c *Client) Snapshot(dsid string, tokens map[string]string) (Session, error) {
	if c.cachedAnisetteHeaders == nil {
		if _, err := c.anisetteHeaders(); err != nil {
			return Session{}, fmt.Errorf("gsa: cannot snapshot session before anisette headers are fetched: %w", err)
		}
	}
	cookies := map[string][]CookieKV{}
	seen := map[string]bool{}
	for _, ustr := range c.requestURLs() {
		u, err := url.Parse(ustr)
		if err != nil {
			continue
		}
		var kvs []CookieKV
		for _, ck := range c.cookieJar.Cookies(u) {
			key := u.Host + "\x00" + ck.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			kvs = append(kvs, CookieKV{Name: ck.Name, Value: ck.Value})
		}
		if len(kvs) > 0 {
			cookies[ustr] = kvs
		}
	}
	return Session{
		AnisetteHeaders: maps.Clone(c.cachedAnisetteHeaders),
		Cookies:         cookies,
		DSID:            dsid,
		Tokens:          maps.Clone(tokens),
	}, nil
}

func NewClientFromSession(anisette AnisetteProvider, sess Session) *Client {
	return NewClientFromSessionWithTransport(anisette, sess, AppleRootTransport().(*http.Transport))
}

// NewClientFromSessionForAccount restores a session on the account's assigned
// route without changing process environment.
func NewClientFromSessionForAccount(anisette AnisetteProvider, sess Session, accountDir string) (*Client, error) {
	transport, err := AppleRootTransportForAccount(accountDir)
	if err != nil {
		return nil, err
	}
	return NewClientFromSessionWithTransport(anisette, sess, transport), nil
}

// NewClientFromSessionWithTransport restores a session with an explicit
// account-scoped transport in shared processes.
func NewClientFromSessionWithTransport(anisette AnisetteProvider, sess Session, transport *http.Transport) *Client {
	c := NewClientWithTransport(anisette, transport)
	if sess.AnisetteHeaders != nil {
		c.cachedAnisetteHeaders = httpx.NormalizeAnisetteHeaders(sess.AnisetteHeaders)
	}
	for ustr, kvs := range sess.Cookies {
		u, err := url.Parse(ustr)
		if err != nil {
			continue
		}
		cks := make([]*http.Cookie, 0, len(kvs))
		for _, kv := range kvs {
			cks = append(cks, &http.Cookie{Name: kv.Name, Value: kv.Value})
		}
		c.cookieJar.SetCookies(u, cks)
	}
	return c
}
