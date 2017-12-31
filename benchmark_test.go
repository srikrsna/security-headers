package secure_test

import (
	"net/http/httptest"
	"testing"

	"github.com/srikrsna/security-headers"
)

func BenchmarkSecure(b *testing.B) {
	s := &secure.Secure{
		STSIncludeSubdomains: true,
		STSPreload:           true,
		STSMaxAgeSeconds:     90,

		FrameOption: secure.FrameAllowFrom,
		FrameOrigin: "https://example.com/",

		ContentTypeNoSniff: true,

		XSSFilterBlock: true,

		HPKPPins: []string{
			"cUPcTAZWKaASuYWhhneDttWpY3oBAkE3h2+soZS7sWs=",
			"M8HztCzM3elUxkcjR2S5P4hhyBNf6lHkmjAHKhpGPWE=",
		},
		HPKPMaxAge:            5184000,
		HPKPReportURI:         "https://www.example.org/hpkp-report",
		HPKPIncludeSubdomains: true,

		ReferrerPolicy: secure.ReferrerStrictOriginWhenCrossOrigin,
	}

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	handler := s.Middleware()(testHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(res, req)
	}
}

func BenchmarkCSP(b *testing.B) {
	csp := &secure.CSP{
		Value: `object-src 'none';
		script-src {{nonce}} 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' https: http:;
		base-uri 'none';
		report-uri https://your-report-collector.example.com/;`,

		ByteSize: 16,
	}

	handler := csp.Middleware()(testHandler)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		res := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		for pb.Next() {
			handler.ServeHTTP(res, req)
		}
	})
}
