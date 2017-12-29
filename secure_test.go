package secure_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/srikrsna/security-headers"
)

var testHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
})

func TestSecureNilHandler(t *testing.T) {
	defer func() {
		err := recover()
		if err == nil {
			t.Errorf("Expected error")
		}
	}()

	s := &secure.Secure{}

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	s.Middleware()(nil).ServeHTTP(res, req)
}

func TestSecure(t *testing.T) {
	tt := []struct {
		name string
		s    *secure.Secure

		outputHeaderKey   string
		outputHeaderValue string
	}{
		{
			name: "TestXSSBlockEnabled",
			s: &secure.Secure{
				XSSFilterBlock: true,
			},
			outputHeaderKey:   "X-XSS-Protection",
			outputHeaderValue: "1; mode=block",
		},
		{
			name: "TestXSSBlockDisabled",
			s: &secure.Secure{
				XSSFilterBlock: false,
			},
			outputHeaderKey:   "X-XSS-Protection",
			outputHeaderValue: "",
		},
		{
			name:              "TestXSSBlockDefault",
			s:                 &secure.Secure{},
			outputHeaderKey:   "X-XSS-Protection",
			outputHeaderValue: "",
		},
		{
			name:              "TestContentTypeHeaderDefault",
			s:                 &secure.Secure{},
			outputHeaderKey:   "X-Content-Type-Options",
			outputHeaderValue: "",
		},
		{
			name: "TestContentTypeHeaderNoSniff",
			s: &secure.Secure{
				ContentTypeNoSniff: true,
			},
			outputHeaderKey:   "X-Content-Type-Options",
			outputHeaderValue: "nosniff",
		},
		{
			name: "TestXFrameOptionsHeaderAllowFrom",
			s: &secure.Secure{
				FrameOption: secure.FrameAllowFrom,
				FrameOrigin: "https://example.com/",
			},
			outputHeaderKey:   "X-Frame-Options",
			outputHeaderValue: "ALLOW-FROM https://example.com/",
		},
		{
			name: "TestXFrameOptionsSameOrigin",
			s: &secure.Secure{
				FrameOption: secure.FrameSameOrigin,
			},
			outputHeaderKey:   "X-Frame-Options",
			outputHeaderValue: "SAMEORIGIN",
		},
		{
			name: "TestXFrameOptionsDeny",
			s: &secure.Secure{
				FrameOption: secure.FrameDeny,
			},
			outputHeaderKey:   "X-Frame-Options",
			outputHeaderValue: "DENY",
		},
		{
			name:              "TestXFrameOptionsDefault",
			s:                 &secure.Secure{},
			outputHeaderKey:   "X-Frame-Options",
			outputHeaderValue: "",
		},
		{
			name: "TestSTSHeaderWithSubDomain",
			s: &secure.Secure{
				STSIncludeSubdomains: true,
				STSMaxAgeSeconds:     90,
			},
			outputHeaderKey:   "Strict-Transport-Security",
			outputHeaderValue: "max-age=90; includeSubDomains",
		},
		{
			name: "TestSTSHeaderWithPreload",
			s: &secure.Secure{
				STSPreload:       true,
				STSMaxAgeSeconds: 90,
			},
			outputHeaderKey:   "Strict-Transport-Security",
			outputHeaderValue: "max-age=90; preload",
		},
		{
			name: "TestSTSHeaderWithSubdomainAndPreload",
			s: &secure.Secure{
				STSPreload:           true,
				STSIncludeSubdomains: true,
				STSMaxAgeSeconds:     90,
			},
			outputHeaderKey:   "Strict-Transport-Security",
			outputHeaderValue: "max-age=90; includeSubDomains; preload",
		},
		{
			name: "TestSTSHeaderWithoutMaxAgeWithSubDomainWithPreload",
			s: &secure.Secure{
				STSPreload:           true,
				STSIncludeSubdomains: true,
			},
			outputHeaderKey:   "Strict-Transport-Security",
			outputHeaderValue: "",
		},
		{
			name: "TestHPKPPinningWithAllSet",
			s: &secure.Secure{
				HPKPPins:              []string{"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=", "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="},
				HPKPMaxAge:            5184000,
				HPKPReportURI:         "https://www.example.org/hpkp-report",
				HPKPIncludeSubdomains: true,
			},

			outputHeaderKey:   "Public-Key-Pins",
			outputHeaderValue: "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; max-age=5184000; includeSubDomains; report-uri=\"https://www.example.org/hpkp-report\"",
		},
		{
			name: "TestHPKPPinningWithoutIncludeSubdomains",
			s: &secure.Secure{
				HPKPPins:      []string{"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=", "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="},
				HPKPMaxAge:    5184000,
				HPKPReportURI: "https://www.example.org/hpkp-report",
			},

			outputHeaderKey:   "Public-Key-Pins",
			outputHeaderValue: "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; max-age=5184000; report-uri=\"https://www.example.org/hpkp-report\"",
		},
		{
			name: "TestHPKPPinningWithSinglePin",
			s: &secure.Secure{
				HPKPPins:      []string{"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs="},
				HPKPMaxAge:    5184000,
				HPKPReportURI: "https://www.example.org/hpkp-report",
			},

			outputHeaderKey:   "Public-Key-Pins",
			outputHeaderValue: "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; max-age=5184000; report-uri=\"https://www.example.org/hpkp-report\"",
		},
		{
			name: "TestHPKPPinningDefault",
			s:    &secure.Secure{},

			outputHeaderKey:   "Public-Key-Pins",
			outputHeaderValue: "",
		},
		{
			name: "TestHPKPPinningReportOnly",
			s: &secure.Secure{
				HPKPPins:       []string{"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=", "M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE="},
				HPKPMaxAge:     5184000,
				HPKPReportURI:  "https://www.example.org/hpkp-report",
				HPKPReportOnly: true,
			},

			outputHeaderKey:   "Public-Key-Pins-Report-Only",
			outputHeaderValue: "pin-sha256=\"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=\"; pin-sha256=\"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=\"; max-age=5184000; report-uri=\"https://www.example.org/hpkp-report\"",
		},
		{
			name: "TestReferrerPolicy",
			s: &secure.Secure{
				ReferrerPolicy: secure.ReferrerStrictOrigin,
			},

			outputHeaderKey:   "Referrer-Policy",
			outputHeaderValue: "strict-origin",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)

			tc.s.Middleware()(testHandler).ServeHTTP(res, req)

			assert(t, res.Code, http.StatusOK)
			assert(t, res.Header().Get(http.CanonicalHeaderKey(tc.outputHeaderKey)), tc.outputHeaderValue)
		})
	}

}

func assert(t *testing.T, f interface{}, s interface{}) {
	// t.Helper() Added in Go 1.9
	if f != s {
		t.Errorf("Expected {%v} of type [%v] - Got {%v} of type [%v]", s, reflect.TypeOf(s), f, reflect.TypeOf(f))
	}
}
