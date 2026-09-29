package funcs

import "net/http"

// Profile defines a browser-inspired User-Agent and request-header set.
// These application-layer values do not reproduce a browser's full network
// fingerprint.
type Profile struct {
	Name      string
	UserAgent string
	Headers   map[string]string
}

// UATransport applies a profile to requests handled by the wrapped transport.
type UATransport struct {
	Base    http.RoundTripper
	Profile Profile
}

// RoundTrip clones the request before applying the selected values. POST and
// JSON requests use fetch-style Sec-Fetch values instead of navigation values.
func (t *UATransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())

	clone.Header.Del("User-Agent")
	clone.Header.Set("User-Agent", t.Profile.UserAgent)

	// Agent API calls use the header shape associated with a browser fetch.
	isFetch := req.Method == "POST" ||
		req.Header.Get("Content-Type") == "application/json"

	for key, val := range t.Profile.Headers {
		if isFetch {
			switch key {
			case "Sec-Fetch-Mode":
				clone.Header.Set(key, "cors")
				continue
			case "Sec-Fetch-Dest":
				clone.Header.Set(key, "empty")
				continue
			case "Sec-Fetch-Site":
				clone.Header.Set(key, "same-origin")
				continue
			case "Sec-Fetch-User":
				continue
			case "Upgrade-Insecure-Requests":
				continue
			case "Accept":
				clone.Header.Set(key, "application/json, */*;q=0.9")
				continue
			}
		}

		clone.Header.Set(key, val)
	}

	return t.Base.RoundTrip(clone)
}

// The profiles are static approximations. Go's HTTP transport controls wire
// encoding and header order.

var Profiles = map[int]Profile{

	// Chrome-style profile for Windows.
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
	},

	// Chrome-style profile for Linux.
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
	},

	// Firefox-style profile for Windows.
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
	},

	// Firefox-style profile for Linux.
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
	},

	// Safari-style profile for macOS.
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
	},
}
