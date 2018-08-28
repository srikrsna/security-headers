package secure

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	cspHeader           = "Content-Security-Policy"
	cspReportOnlyHeader = "Content-Security-Policy-Report-Only"
)

// NonceToken is the string token that gets replaced by the middleware with a dynamic nonce directive
const NonceToken = "{{nonce}}"

var nonceReplacer = strings.NewReplacer(NonceToken, "'nonce-%[1]s'")

// CSP is used to configure the Content Security Policy Middleware. For more about csp please refer the mozilla docs.
type CSP struct {
	// Value is the CSP header value.Eg: script-src {{nonce}} 'strict-dynamic'; object-src 'none';
	// If the Value contains '{{nonce}}', it will be replaced by a dynamic nonce {{nonce}} -> 'nonce-jagflah+==' every request.
	//
	// Generated nonce can be obtained using the `Nonce(context.Context)` function.
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
	byteSize     int64
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

	cfg.template = nonceReplacer.Replace(c.Value)

	cfg.nonceEnabled = strings.Contains(cfg.template, "%[1]s")

	if c.ByteSize <= 0 {
		c.ByteSize = 16
	}
	cfg.byteSize = int64(c.ByteSize)

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
				buff := bufferPool.Get().(*bytes.Buffer)

				buff.Reset()
				CryptoRandNonce(buff, cfg.byteSize)

				nonce := buff.Bytes()

				w.Header().Add(cfg.headerKey, fmt.Sprintf(cfg.template, nonce))

				ctx := WithNonce(r.Context(), string(nonce))
				r = r.WithContext(ctx)

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
// Typical usecase would be to use this method to create own handlers/middlewares for packages that don't support net/http.
// Note: To get the nonce associated with the present request use `Nonce(context.Context)` method.
//
// Important: This function is no longer used to generate the Nonce. Please refer to this issue: https://github.com/srikrsna/security-headers/issues/5
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
}

// CryptoRandNonce writes the cryptographically generated random nonce of length 'n' to the provided Writer.
// Typical usecase would be to use this method to create own handlers/middlewares for packages that don't support net/http.
// Note: To get the nonce associated with the present request use `Nonce(context.Context)` method.
func CryptoRandNonce(w io.Writer, n int64) {
	b := make([]byte, n)
	if _, err := io.ReadFull(crand.Reader, b); err != nil {
		panic("secure: " + err.Error())
	}

	enc := base64.NewEncoder(base64.RawStdEncoding, w)
	enc.Write(b)
	enc.Close()
}

// Nonce returns the nonce value present in the context. If no nonce is present it returns an empty string.
func Nonce(c context.Context) string {
	if val, ok := c.Value(nonceKey).(string); ok {
		return val
	}

	return ""
}

// WithNonce is convenience method that can be
func WithNonce(ctx context.Context, n string) context.Context {
	return context.WithValue(ctx, nonceKey, n)
}
