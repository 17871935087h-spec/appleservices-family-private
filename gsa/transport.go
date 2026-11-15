package gsa

import "net/http"

// The GSA service can reject the second request on a reused connection with 429.
// Keep cookies, proxy configuration, and certificate verification; retire only
// connections used by gsa.apple.com after each response.
type authenticationTransport struct {
	shared *http.Transport
	gsa    *http.Transport
}

func newAuthenticationTransport() *authenticationTransport {
	shared := AppleRootTransport().(*http.Transport)
	return newAuthenticationTransportWithBase(shared)
}

func newAuthenticationTransportWithBase(shared *http.Transport) *authenticationTransport {
	if shared == nil {
		shared = AppleRootTransport().(*http.Transport)
	}
	unpooled := shared.Clone()
	unpooled.DisableKeepAlives = true
	// An HTTP/2 connection can carry multiple authentication requests. Pin GSA
	// to HTTP/1 so Connection: close also closes the TLS/proxy tunnel each time.
	unpooled.Protocols = new(http.Protocols)
	unpooled.Protocols.SetHTTP1(true)
	return &authenticationTransport{shared: shared, gsa: unpooled}
}

func (t *authenticationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Hostname() != "gsa.apple.com" {
		return t.shared.RoundTrip(request)
	}
	copy := request.Clone(request.Context())
	copy.Close = true
	return t.gsa.RoundTrip(copy)
}
