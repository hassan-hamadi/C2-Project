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
//
// Sec-Fetch context selection: the profile stores navigation-context values
// (navigate/document/none) which are correct for top-level page loads. For
// POST requests and JSON API calls the agent uses a fetch context
// (cors/empty/same-origin) instead, because a real browser would never send
// navigate+document on a programmatic fetch() or XHR call. Sending the wrong
// context is a logical impossibility that IDS tools flag as a spoofing signal.
func (t *UATransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())

	// Get rid of Go's default User-Agent header before we set our own
	clone.Header.Del("User-Agent")
	clone.Header.Set("User-Agent", t.Profile.UserAgent)

	// All agent-to-server calls are POST with a JSON body, which means they
	// originate from JavaScript (fetch/XHR context), not a page navigation.
	isFetch := req.Method == "POST" ||
		req.Header.Get("Content-Type") == "application/json"

	for _, key := range t.Profile.HeaderOrder {
		val, ok := t.Profile.Headers[key]
		if !ok {
			continue
		}

		if isFetch {
			switch key {
			case "Sec-Fetch-Mode":
				// navigate is for page loads; cors is for cross-origin fetch/XHR
				clone.Header.Set(key, "cors")
				continue
			case "Sec-Fetch-Dest":
				// document is for page loads; empty is for fetch/XHR with no dest
				clone.Header.Set(key, "empty")
				continue
			case "Sec-Fetch-Site":
				// none is for address-bar navigations; same-origin is for JS on
				// the same origin making a fetch call back to its own server
				clone.Header.Set(key, "same-origin")
				continue
			case "Sec-Fetch-User":
				// Only sent on user-initiated navigations (an actual click).
				// Never present on programmatic fetch/XHR calls, so drop it.
				continue
			case "Upgrade-Insecure-Requests":
				// Tells the server the browser accepts an HTTPS upgrade on page
				// loads. Meaningless and anomalous on a JSON POST, so drop it.
				continue
			case "Accept":
				// Navigation Accept advertises HTML preference. fetch() calls
				// from JavaScript advertise JSON preference instead.
				clone.Header.Set(key, "application/json, */*;q=0.9")
				continue
			}
		}

		clone.Header.Set(key, val)
	}

	return t.Base.RoundTrip(clone)
}

// Each profile below matches what that real browser actually sends as of
// April 2026, including which headers are present and which are not.
// HeaderOrder stores the real ordering so we can enforce it later when
// the transport layer supports it (planned for the HTTPS/uTLS update).
// The Sec-Fetch values here reflect a top-level navigation. RoundTrip
// automatically overrides them for fetch/XHR requests (cors/empty/same-origin).

var Profiles = map[int]Profile{

	// Chrome 147 on Windows (stable build 147.0.7727.55, released April 7 2026)
	1: {
		Name:      "Chrome/Windows",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.55 Safari/537.36",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Connection":                "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Ch-Ua":                 `"Chromium";v="147", "Google Chrome";v="147", "Not-A.Brand";v="24"`,
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

	// Chrome 147 on Linux (stable build 147.0.7727.55, released April 7 2026)
	2: {
		Name:      "Chrome/Linux",
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.7727.55 Safari/537.36",
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Connection":                "keep-alive",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Ch-Ua":                 `"Chromium";v="147", "Google Chrome";v="147", "Not-A.Brand";v="24"`,
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
