package secure_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/srikrsna/security-headers"
)

func TestCSPNonce(t *testing.T) {
	for byteAmount := 1; byteAmount < 2; byteAmount++ {
		t.Run(fmt.Sprintf("TestCSPNonceByteAmount%d", byteAmount), func(t *testing.T) {
			s := secure.CSP{
				Value:      "default-src 'self' {{ . }}; script-src 'strict-dynamic' {{ . }}",
				ByteAmount: byteAmount,
			}

			res := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/foo", nil)

			s.Middleware()(testHandler).ServeHTTP(res, req)

			assert(t, res.Code, http.StatusOK)
			assert(t, len(secure.Nonce(req)), base64.StdEncoding.EncodedLen(byteAmount))
			assert(t, res.Header().Get("Content-Security-Policy"), fmt.Sprintf("default-src 'self' 'nonce-%[1]s'; script-src 'strict-dynamic' 'nonce-%[1]s'", secure.Nonce(req)))
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
	defer func() {
		err := recover()
		if err == nil {
			t.Errorf("Expected error")
		}
	}()

	csp := secure.CSP{
		Value:      "{{ .Name }}",
		ByteAmount: 32,
	}

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	csp.Middleware()(testHandler).ServeHTTP(res, req)
}

func TestCSPNilHandler(t *testing.T) {
	defer func() {
		err := recover()
		if err == nil {
			t.Errorf("Expected error")
		}
	}()

	csp := secure.CSP{
		Value:      "script-src 'none';",
		ByteAmount: 32,
	}

	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)

	csp.Middleware()(nil).ServeHTTP(res, req)
}
