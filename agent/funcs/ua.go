package funcs

import "net/http"

// Profile holds everything needed to impersonate a specific browser.
// That includes the User-Agent string, the supporting headers that
// real browsers send alongside it, and the order those headers appear
// in actual traffic. The profile gets picked at build time and applied
// to every request the agent sends.
type Profile struct {
	Name        string
	UserAgent   string
	Headers     map[string]string
	HeaderOrder []string
}

// UATransport sits between the agent and the network. Every time the
// agent makes an HTTP request, this intercepts it and swaps in the
// browser profile headers before anything goes out. Wrapping
// http.DefaultTransport means all existing call sites (http.Post,
// http.Get, etc.) get the spoofed headers automatically, no changes
// needed at each call site.
type UATransport struct {
	Base    http.RoundTripper
	Profile Profile
}

// RoundTrip runs on every outgoing request. It clones the request first
// (the RoundTripper interface requires that you never modify the original),
// then strips Go's default User-Agent and applies the full profile.
func (t *UATransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())

	// Get rid of Go's default User-Agent header before we set our own
	clone.Header.Del("User-Agent")

	clone.Header.Set("User-Agent", t.Profile.UserAgent)

	// Apply the rest of the profile headers in the right order
	for _, key := range t.Profile.HeaderOrder {
		if val, ok := t.Profile.Headers[key]; ok {
			clone.Header.Set(key, val)
		}
	}

	return t.Base.RoundTrip(clone)
}

// Each profile below matches what that real browser actually sends as of
// April 2026, including which headers are present and which are not.
// HeaderOrder stores the real ordering so we can enforce it later when
// the transport layer supports it (planned for the HTTPS/uTLS update).

var Profiles = map[int]Profile{

	// Chrome 147 on Windows
	1: {
		Name:      "Chrome/Windows",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Connection":                "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Ch-Ua":                 `"Chromium";v="147", "Google Chrome";v="147", "Not-A.Brand";v="99"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"Windows"`,
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
		},
		HeaderOrder: []string{
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Connection",
			"Sec-Ch-Ua",
			"Sec-Ch-Ua-Mobile",
			"Sec-Ch-Ua-Platform",
			"Sec-Fetch-Dest",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Site",
			"Sec-Fetch-User",
			"Upgrade-Insecure-Requests",
		},
	},

	// Chrome 147 on Linux
	2: {
		Name:      "Chrome/Linux",
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Connection":                "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Ch-Ua":                 `"Chromium";v="147", "Google Chrome";v="147", "Not-A.Brand";v="99"`,
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        `"Linux"`,
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
		},
		HeaderOrder: []string{
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Connection",
			"Sec-Ch-Ua",
			"Sec-Ch-Ua-Mobile",
			"Sec-Ch-Ua-Platform",
			"Sec-Fetch-Dest",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Site",
			"Sec-Fetch-User",
			"Upgrade-Insecure-Requests",
		},
	},

	// Firefox 149 on Windows. Note that Firefox does not send Sec-Ch-Ua
	// client hint headers at all, so they are intentionally left out here.
	3: {
		Name:      "Firefox/Windows",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Connection":                "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
		},
		HeaderOrder: []string{
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Connection",
			"Sec-Fetch-Dest",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Site",
			"Sec-Fetch-User",
			"Upgrade-Insecure-Requests",
		},
	},

	// Firefox 149 on Linux
	4: {
		Name:      "Firefox/Linux",
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Connection":                "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
		},
		HeaderOrder: []string{
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Connection",
			"Sec-Fetch-Dest",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Site",
			"Sec-Fetch-User",
			"Upgrade-Insecure-Requests",
		},
	},

	// Safari 26 on macOS. Apple intentionally freezes the OS version in the
	// UA string to 10_15_7 no matter what macOS version is actually running.
	// This is Apple's own anti-fingerprinting measure, so we match it exactly.
	// Safari also does not send Sec-Ch-Ua headers.
	5: {
		Name:      "Safari/macOS",
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Connection":                "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
		},
		HeaderOrder: []string{
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Connection",
			"Sec-Fetch-Dest",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Site",
			"Sec-Fetch-User",
			"Upgrade-Insecure-Requests",
		},
	},
}
