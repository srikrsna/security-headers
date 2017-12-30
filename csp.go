package secure

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

// CSP is used to configure the Content Security Policy Middleware. For more about csp please refer the mozilla docs.
type CSP struct {
	// Value is the CSP header value.Eg: script-src {{ . }} 'strict-dynamic'; object-src 'none';
	// If the Value contains '{{ . }}', it will be replaced by a dynamic nonce {{ . }} -> 'nonce-jagflah+==' every request.
	//
	// Generated nonce can be obtained using the `Nonce(*http.Request)` function.
	Value string

	// ByteSize is the size of the nonce being generated in bytes. If passed <= '0' it will chnage to 16.
	// Default is 16.
	ByteSize int

	// ReportOnly will send report only header (Content-Security-Policy-Report-Only) instead of the regular header (Content-Security-Policy-Report-Only).
	// Enabling this option will result in browsers only reporting violation. Report-URI must be set along with this. Default is false.
	// Note: Package will not check for report-uri
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

var randPool = sync.Pool{
	New: func() interface{} {
		return rand.NewSource(time.Now().UnixNano())
	},
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Middleware return a fuction that adds the configured csp headers, stores the nonce in th request context if configures, and passes the request to the next handler
func (c *CSP) Middleware() func(http.Handler) http.Handler {

	cfg := cspConfig{}

	tmpl := template.Must(template.New("csp").Parse(c.Value))

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, "'nonce-%[1]s'"); err != nil {
		panic(err)
	}

	cfg.template = buffer.String()

	cfg.nonceEnabled = strings.Contains(cfg.template, "%[1]s")

	if c.ByteSize <= 0 {
		c.ByteSize = 16
	}
	cfg.byteAmount = c.ByteSize

	if c.ReportOnly {
		cfg.headerKey = cspReportOnlyHeader
	} else {
		cfg.headerKey = cspHeader
	}

	return cfg.middleware()
}

func (cfg *cspConfig) middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		if next == nil {
			panic("security-handlers: handler is nil")
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			if cfg.nonceEnabled {
				buff := bufferPool.Get().(*bytes.Buffer) // TODO: Go 1.10 -> Change bytes.Buffer to strings.Builder

				buff.Reset()
				RandNonce(buff, cfg.byteAmount)

				nonce := buff.Bytes()
				w.Header().Add(cfg.headerKey, fmt.Sprintf(cfg.template, nonce))

				ctx := context.WithValue(r.Context(), nonceKey, string(nonce))
				*r = *r.WithContext(ctx)

				bufferPool.Put(buff)

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

// RandNonce writes the randomly generated nonce of length 'b' to the provided ByteWriter.
// Typical usecase would be to use this method to create own handlers/middlewares for packages apart from net/http.
// Note: To get the nonce associated with the present request use `Nonce(*http.Request)` method.
func RandNonce(w io.ByteWriter, b int) {

	src := randPool.Get().(rand.Source)

	n := (b*8 + 5) / 6

	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			w.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	randPool.Put(src)

	for i := ((n + 3) & ^3) - n; i > 0; i-- {
		w.WriteByte('=')
	}
}

// Nonce returns the nonce value associated with the present request. If no nonce has been generated it returns an empty string.
func Nonce(r *http.Request) string {
	if val, ok := r.Context().Value(nonceKey).(string); ok {
		return val
	}

	return ""
}
