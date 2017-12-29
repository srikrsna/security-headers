package secure_test

import (
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/srikrsna/security-headers"
)

// Sample showing integration with the awesome router go-chi
func Example_chi() {
	mux := chi.NewMux()

	s := &secure.Secure{
		ContentTypeNoSniff: true,
	}

	mux.Use(s.Middleware())

	mux.Get("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Ok with Headers")
	})

	http.ListenAndServe(":8080", mux)
}

// Sample showing integration with the net/http
func Example_netHttp() {
	mux := http.NewServeMux()

	s := &secure.Secure{
		ContentTypeNoSniff: true,
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Ok with Headers")
	})

	http.ListenAndServe(":8080", s.Middleware()(mux))
}

func ExampleSecure_Middleware() {
	mux := http.NewServeMux()

	s := &secure.Secure{
		ContentTypeNoSniff: true,
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Ok with Headers")
	})

	http.ListenAndServe(":8080", s.Middleware()(mux))
}

func ExampleCSP_Middleware() {
	mux := http.NewServeMux()

	csp := &secure.CSP{
		Value:      `object-src 'none'; script-src {{ . }} 'strict-dynamic'; base-uri 'self'; report-uri https://appointy.com/_csp;`,
		ByteAmount: 8,
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Base64 nonce: %s", secure.Nonce(r))
	})

	http.ListenAndServe(":8080", csp.Middleware()(mux))
}
