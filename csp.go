package secure

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"
)

const (
	cspHeader           = "Content-Security-Policy"
	cspReportOnlyHeader = "Content-Security-Policy-Report-Only"
)

// CSP is the middleware comntaining the csp headers
type CSP struct {
	// Value is the CSP header value.Eg: script-src {{ . }} 'strict-dynamic'; object-src 'none';
	// If the Value contains '{{ . }}', it will be replaced by a dynamic nonce {{ . }} -> 'nonce-jagflah+==' every request.
	//
	// Generated nonce can be obtained using the `Nonce` function.
	Value string

	// ByteAmount is the byte size of the nonce being generated defaults to 16
	ByteAmount int

	// ReportOnly will send report only header. Default is false.
	ReportOnly bool
}

type cspConfig struct {
	template     string
	byteAmount   int
	nonceEnabled bool

	headerKey string

	randPool *sync.Pool
}

type key int

const nonceKey key = iota

var once sync.Once

var randPool sync.Pool

// Middleware return a fuction that takes a http handler and returns a http handler
func (c *CSP) Middleware() func(http.Handler) http.Handler {

	cfg := cspConfig{}

	tmpl := template.Must(template.New("csp").Parse(c.Value))

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, "'nonce-%[1]s'"); err != nil {
		panic(err)
	}

	cfg.template = buffer.String()

	cfg.nonceEnabled = strings.Contains(cfg.template, "%[1]s")

	if c.ByteAmount <= 0 {
		c.ByteAmount = 16
	}
	cfg.byteAmount = c.ByteAmount

	if c.ReportOnly {
		cfg.headerKey = cspReportOnlyHeader
	} else {
		cfg.headerKey = cspHeader
	}

	once.Do(func() {
		randPool = sync.Pool{
			New: func() interface{} {
				return rand.NewSource(time.Now().UnixNano())
			},
		}
	})

	return cfg.middleware()
}

func (cfg *cspConfig) middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		if next == nil {
			panic("security-handlers: handler is nil")
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if cfg.nonceEnabled {
				// nonce := randNonce(rand.NewSource(time.Now().UnixNano()), cfg.byteAmount)
				nonce := randNonce(cfg.byteAmount)
				ctx := context.WithValue(r.Context(), nonceKey, nonce)
				*r = *r.WithContext(ctx)

				w.Header().Add(cfg.headerKey, fmt.Sprintf(cfg.template, nonce))

				next.ServeHTTP(w, r)
				return
			}

			w.Header().Add(cfg.headerKey, cfg.template)
			next.ServeHTTP(w, r)
		})
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func randNonce(byteLen int) string {

	src := randPool.Get().(rand.Source)

	n := (byteLen*8 + 5) / 6

	b := make([]byte, (n+3) & ^3)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	randPool.Put(src)

	for i := len(b) - n; i > 0; i-- {
		b[n+i-1] = '='
	}

	return string(b)
}

// Nonce returns the nonce value associated with the present request. If no nonce has been generated it returns an empty string.
func Nonce(r *http.Request) string {
	if val, ok := r.Context().Value(nonceKey).(string); ok {
		return val
	}

	return ""
}
