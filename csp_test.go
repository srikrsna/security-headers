package secure_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/srikrsna/security-headers"
)

func TestCSPDefaultNonce(t *testing.T) {

	req, _ := http.NewRequest("GET", "/foo", nil)

	assert(t, secure.Nonce(req.Context()), "")
}

func TestCSPNonce(t *testing.T) {
	for byteAmount := 1; byteAmount < 20; byteAmount++ {
		t.Run(fmt.Sprintf("TestCSPNonceByteAmount%d", byteAmount), func(t *testing.T) {
			s := secure.CSP{
				Value:    "default-src 'self' {{nonce}}; script-src 'strict-dynamic' {{nonce}}",
				ByteSize: byteAmount,
			}

			res := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/foo", nil)

			nonce := ""

			s.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nonce = secure.Nonce(r.Context())
				assert(t, len(secure.Nonce(r.Context())), base64.RawStdEncoding.EncodedLen(byteAmount))
			})).ServeHTTP(res, req)

			assert(t, res.Code, http.StatusOK)
			assert(t, res.Header().Get("Content-Security-Policy"), fmt.Sprintf("default-src 'self' 'nonce-%[1]s'; script-src 'strict-dynamic' 'nonce-%[1]s'", nonce))
		})
	}
}

func TestCSPDefault(t *testing.T) {

	s := secure.CSP{}

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Middleware()(testHandler).ServeHTTP(res, req)

	assert(t, res.Code, http.StatusOK)
	assert(t, res.Header().Get("Content-Security-Policy-Report-Only"), "")
	assert(t, res.Header().Get("Content-Security-Policy"), "")
}

func TestCSP(t *testing.T) {

	s := secure.CSP{
		Value: "script-src 'self'",
	}

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Middleware()(testHandler).ServeHTTP(res, req)

	assert(t, res.Code, http.StatusOK)
	assert(t, res.Header().Get("Content-Security-Policy-Report-Only"), "")
	assert(t, res.Header().Get("Content-Security-Policy"), "script-src 'self'")
}

func TestCSPReportOnly(t *testing.T) {

	s := secure.CSP{
		Value:      "script-src 'self'",
		ReportOnly: true,
	}

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Middleware()(testHandler).ServeHTTP(res, req)

	assert(t, res.Code, http.StatusOK)
	assert(t, res.Header().Get("Content-Security-Policy-Report-Only"), "script-src 'self'")
	assert(t, res.Header().Get("Content-Security-Policy"), "")
}

func TestCSPWrongTemplate(t *testing.T) {
	csp := secure.CSP{
		Value:    "{{ .Name }}",
		ByteSize: 32,
	}

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	csp.Middleware()(testHandler).ServeHTTP(res, req)

	assert(t, res.Header().Get("Content-Security-Policy"), "{{ .Name }}")
}

func TestCSPNilHandler(t *testing.T) {
	defer func() {
		err := recover()
		if err == nil {
			t.Errorf("Expected error")
		}
	}()

	csp := secure.CSP{
		Value:    "script-src 'none';",
		ByteSize: 32,
	}

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	csp.Middleware()(nil).ServeHTTP(res, req)
}
