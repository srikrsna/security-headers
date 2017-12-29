[![Go Report Card](https://goreportcard.com/badge/github.com/srikrsna/security-headers)](https://goreportcard.com/report/github.com/srikrsna/security-headers) [![Build Status](https://travis-ci.org/srikrsna/security-headers.svg?branch=master)](https://travis-ci.org/srikrsna/security-headers)

# Security Headers

HTTP middleware for Go providing various security headers. It's 100% compatible with `net/http` package and various other routers. Requires a minimum of Go 1.7

## Usage

### Dynamic Content Security Policy

Headers like Strict Transport Policy seldom change but Content Security Policy's [nonce directive](https://csp.withgoogle.com/docs/strict-csp.html) needs to be randomized for every request. In addition to this, same nonce value must also be on html tags `<scritpt nonce="2hgoUhs/="> ... </script>`.

Hence it is more practical to perform this at this level than in a reverse proxy. Due to this Content Security Policy Header or CSP has been separated from other security headers.

~~~ go
func main() {
    mux := http.NewServeMux()

    csp := &secure.CSP{
        Value:      `object-src 'none'; script-src {{ . }} 'strict-dynamic'; base-uri 'self'; report-uri https://example.com/_csp;`,
        ByteAmount: 8,
    }

    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Base64 nonce: %s", secure.Nonce(r)) // secure.Nonce(*http.Request) returns Nonce associated with the present request Object
    })

    http.ListenAndServe(":8080", csp.Middleware()(mux))
}
~~~

### Static Headers

Headers that are better off implemented in a Reverse Proxy, such as Ngnix, in case of one.

~~~ go
// main.go
func main() {
    mux := http.NewServeMux()

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

    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        io.WriteString(w, "Ok with Security Headers")
    })

    http.ListenAndServe(":8080", s.Middleware()(mux))
}
~~~

### Configuration options

For various configuration options and other integration examples please refer the [godoc](https://godoc.org/github.com/srikrsna/security-headers).
