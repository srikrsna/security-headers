package secure

import (
	"fmt"
	"net/http"
)

const (
	stsHeader = "Strict-Transport-Security"

	frameOptionsHeader = "X-Frame-Options"

	contentTypeHeader = "X-Content-Type-Options"

	xssProtectionHeader = "X-XSS-Protection"

	hpkpHeader           = "Public-Key-Pins"
	hpkpReportOnlyHeader = "Public-Key-Pins-Report-Only"

	referrerPolicyHeader = "Referrer-Policy"

	expectCTHeader = "Expect-CT"
)

const (
	stsIncludeSubdomainValue = "; includeSubDomains"
	stsPreloadValue          = "; preload"
)

const (
	contentTypeNoSniffValue = "nosniff"
	xssFilterBlockValue     = "1; mode=block"
)

const (
	hpkpIncludeSubdomainValue = "; includeSubDomains"
)

const (
	expectCTEnforceValue = ", enforce"
)

type frameOption string

const (
	// FrameSameOrigin is the SAMEORIGIN XFrameOption
	FrameSameOrigin frameOption = "SAMEORIGIN"
	// FrameDeny is the DENY XFrameOption
	FrameDeny frameOption = "DENY"
	// FrameAllowFrom is the DENY XFrameOption, if this is set then the XFrameOrigin must also be set
	FrameAllowFrom frameOption = "ALLOW-FROM"
)

type referrerPolicy string

const (
	// ReferrerNoReferrer will lead to the omiision of referrer information entirely.
	// No referrer information is sent along with requests.
	ReferrerNoReferrer referrerPolicy = "no-referrer"

	// ReferrerNoReferrerWhenDowngrade is the user agent's default behavior if no policy is specified.
	// The origin is sent as referrer to a-priori as-much-secure destination (HTTPS->HTTPS),
	// but isn't sent to a less secure destination (HTTPS->HTTP)
	ReferrerNoReferrerWhenDowngrade referrerPolicy = "no-referrer-when-downgrade"

	// ReferrerOrigin only sends the origin of the document as the referrer in all cases.
	// The document https://example.com/page.html will send the referrer https://example.com/.
	ReferrerOrigin referrerPolicy = "origin"

	// ReferrerOriginWhenCrossOrigin sends a full URL when performing a same-origin request,
	// but only sends the origin of the document for other cases.
	ReferrerOriginWhenCrossOrigin referrerPolicy = "origin-when-cross-origin"

	// ReferrerSameOrigin will send a referrer to same-site origins,
	// but cross-origin requests will contain no referrer information.
	ReferrerSameOrigin referrerPolicy = "same-origin"

	// ReferrerStrictOrigin only sends the origin of the document as the referrer to a-priori as-much-secure destination (HTTPS->HTTPS),
	// but won't send it to a less secure destination (HTTPS->HTTP).
	ReferrerStrictOrigin referrerPolicy = "strict-origin"

	// ReferrerStrictOriginWhenCrossOrigin sends a full URL when performing a same-origin request,
	// only sends the origin of the document to a-priori as-much-secure destination (HTTPS->HTTPS),
	// and sends no header to a less secure destination (HTTPS->HTTP).
	ReferrerStrictOriginWhenCrossOrigin referrerPolicy = "strict-origin-when-cross-origin"

	// ReferrerUnsafeURL sends a full URL when performing a same-origin or cross-origin request.
	// NOTE: This policy will leak origins and paths from TLS-protected resources to insecure origins.
	// Carefully consider the impact of this setting.
	ReferrerUnsafeURL referrerPolicy = "unsafe-url"
)

// Secure is the middleware containing the configuration for the setup of various security headers
type Secure struct {
	STSMaxAgeSeconds     uint64
	STSIncludeSubdomains bool
	STSPreload           bool

	FrameOption frameOption
	FrameOrigin string

	ContentTypeNoSniff bool

	XSSFilterBlock bool

	HPKPPins              []string
	HPKPReportOnly        bool
	HPKPMaxAge            uint64
	HPKPIncludeSubdomains bool
	HPKPReportURI         string

	ExpectCTMaxAge    int
	ExpectCTEnforce   bool
	ExpectCTReportUri string

	ReferrerPolicy referrerPolicy
}

type config struct {
	shouldSts bool
	stsValue  string

	shouldXFrame bool
	xFrameValue  string

	shouldcontentType bool

	shouldXSSProtection bool

	shouldHPKP bool
	hpkpValue  string
	hpkpHeader string

	shouldReferrer      bool
	referrerPolicyValue string

	shouldCT      bool
	expectCTValue string
}

// Middleware returns a function that takes a http.Middleware returns a http.Middleware
func (s *Secure) Middleware() func(http.Handler) http.Handler {

	var cfg config

	if s.STSMaxAgeSeconds > 0 {

		cfg.shouldSts = true

		if s.STSIncludeSubdomains {
			cfg.stsValue += stsIncludeSubdomainValue
		}

		if s.STSPreload {
			cfg.stsValue += stsPreloadValue
		}

		cfg.stsValue = fmt.Sprintf("max-age=%d%s", s.STSMaxAgeSeconds, cfg.stsValue)
	}

	switch s.FrameOption {
	case FrameSameOrigin:
		cfg.shouldXFrame = true
		cfg.xFrameValue = string(FrameSameOrigin)
	case FrameDeny:
		cfg.shouldXFrame = true
		cfg.xFrameValue = string(FrameDeny)
	case FrameAllowFrom:
		cfg.shouldXFrame = true
		cfg.xFrameValue = string(FrameAllowFrom) + " " + s.FrameOrigin
	}

	cfg.shouldcontentType = s.ContentTypeNoSniff

	cfg.shouldXSSProtection = s.XSSFilterBlock

	if s.HPKPMaxAge > 0 && len(s.HPKPPins) > 0 {
		cfg.shouldHPKP = true

		for _, pin := range s.HPKPPins {
			cfg.hpkpValue = fmt.Sprintf("%s pin-sha256=\"%s\";", cfg.hpkpValue, pin)
		}

		cfg.hpkpValue = cfg.hpkpValue[1:]
		cfg.hpkpValue = fmt.Sprintf("%s max-age=%d", cfg.hpkpValue, s.HPKPMaxAge)

		if s.HPKPIncludeSubdomains {
			cfg.hpkpValue = fmt.Sprintf("%s%s", cfg.hpkpValue, hpkpIncludeSubdomainValue)
		}

		if len(s.HPKPReportURI) > 0 {
			cfg.hpkpValue = fmt.Sprintf("%s; report-uri=\"%s\"", cfg.hpkpValue, s.HPKPReportURI)
		}

		if s.HPKPReportOnly {
			cfg.hpkpHeader = hpkpReportOnlyHeader
		} else {
			cfg.hpkpHeader = hpkpHeader
		}
	}

	if len(s.ReferrerPolicy) > 0 {
		cfg.shouldReferrer = true
		cfg.referrerPolicyValue = string(s.ReferrerPolicy)
	}

	if s.ExpectCTMaxAge > 0 {
		cfg.shouldCT = true
		cfg.expectCTValue = fmt.Sprintf("max-age=%d", s.ExpectCTMaxAge)

		if s.ExpectCTEnforce {
			cfg.expectCTValue += expectCTEnforceValue
		}

		if len(s.ExpectCTReportUri) > 0 {
			cfg.expectCTValue += ", report-uri=\"" + s.ExpectCTReportUri + "\""
		}
	}

	return middleware(&cfg)
}

func middleware(cfg *config) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		if next == nil {
			panic("security-handlers: handler is nil")
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if cfg.shouldSts {
				w.Header().Add(stsHeader, cfg.stsValue)
			}

			if cfg.shouldXFrame {
				w.Header().Add(frameOptionsHeader, cfg.xFrameValue)
			}

			if cfg.shouldcontentType {
				w.Header().Add(contentTypeHeader, contentTypeNoSniffValue)
			}

			if cfg.shouldXSSProtection {
				w.Header().Add(xssProtectionHeader, xssFilterBlockValue)
			}

			if cfg.shouldHPKP {
				w.Header().Add(cfg.hpkpHeader, cfg.hpkpValue)
			}

			if cfg.shouldReferrer {
				w.Header().Add(referrerPolicyHeader, cfg.referrerPolicyValue)
			}

			if cfg.shouldCT {
				w.Header().Add(expectCTHeader, cfg.expectCTValue)
			}

			next.ServeHTTP(w, r)
		})
	}
}
