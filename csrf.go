package csrf

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type (
	// CSRFConfig defines the config for CSRF middleware
	CSRFConfig struct {
		TokenLength uint8 `yaml:"token_length"`
		// Optional. Default value 32.

		// TokenLookup is a string in the form of "<source>:<key>" that is used
		// to extract token from the request.
		// Optional. Default value "header:X-CSRF-Token".
		// Possible values:
		// - "header:<name>"
		// - "form:<name>"
		// - "query:<name>"
		TokenLookup string `yaml:"token_lookup"`

		// Context key to store generated CSRF token into context.
		// Optional. Default value "csrf".
		ContextKey string `yaml:"context_key"`

		// Name of the CSRF cookie. This cookie will store CSRF token.
		// Optional. Default value "csrf".
		CookieName string `yaml:"cookie_name"`

		// Domain of the CSRF cookie.
		// Optional. Default value none.
		CookieDomain string `yaml:"cookie_domain"`

		// Path of the CSRF cookie.
		// Optional. Default value none.
		CookiePath string `yaml:"cookie_path"`

		// Max age (in seconds) of the CSRF cookie.
		// Optional. Default value 86400 (24hr).
		CookieMaxAge int `yaml:"cookie_max_age"`

		// Indicates if CSRF cookie is secure.
		// Optional. Default value false.
		CookieSecure bool `yaml:"cookie_secure"`

		// Indicates if CSRF cookie is HTTP only.
		// Optional. Default value false.
		CookieHTTPOnly bool `yaml:"cookie_http_only"`
	}

	// either a token or an error.
	csrfTokenExtractor func(req *http.Request) ([]byte, error)
)

const (
	// CSRFTokenNotFound defines the error for a Token not found
	CSRFTokenNotFound = "CSRF Token not found"

	// DefaultTokenLookup defines `X-CSRF-TOKEN` as the default token lookup
	DefaultTokenLookup = "X-CSRF-TOKEN"

	// InvalidCSRFToken defines the error for an invalid CSRF token
	InvalidCSRFToken = "Invalid token"
)

var (
	// DefaultCSRFConfig is the default CSRF middleware config.
	DefaultCSRFConfig = CSRFConfig{
		TokenLength:  32,
		TokenLookup:  "header:" + DefaultTokenLookup,
		ContextKey:   "csrf",
		CookieName:   "_csrf",
		CookieMaxAge: 86400,
	}
)

// CSRF returns a Cross-Site Request Forgery (CSRF) middleware.
// See: https://en.wikipedia.org/wiki/Cross-site_request_forgery
func CSRF(next http.Handler) http.Handler {
	c := DefaultCSRFConfig
	return CSRFWithConfig(c)(next)
}

// CSRFWithConfig returns a CSRF middleware with config.
// See `CSRF(fasthttp.RequestHandler)`.
func CSRFWithConfig(config CSRFConfig) func(next http.Handler) http.Handler {
	if config.TokenLength == 0 {
		config.TokenLength = DefaultCSRFConfig.TokenLength
	}
	if config.TokenLookup == "" {
		config.TokenLookup = DefaultCSRFConfig.TokenLookup
	}
	if config.ContextKey == "" {
		config.ContextKey = DefaultCSRFConfig.ContextKey
	}
	if config.CookieName == "" {
		config.CookieName = DefaultCSRFConfig.CookieName
	}
	if config.CookieMaxAge == 0 {
		config.CookieMaxAge = DefaultCSRFConfig.CookieMaxAge
	}
	// Initialize
	parts := strings.Split(config.TokenLookup, ":")
	extractor := csrfTokenFromHeader(parts[1])
	switch parts[0] {
	case "form":
		extractor = csrfTokenFromForm(parts[1])

	case "query":
		extractor = csrfTokenFromQuery(parts[1])
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			method := req.Method

			token := ""
			if k, err := req.Cookie(config.CookieName); err != nil {
				token = randomString(config.TokenLength)
			} else {
				token = k.Value // Reuse token
			}

			log.Println(method)

			switch string(method) {
			case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			default:
				// Validate token only for requests which are not defined as 'safe' by RFC7231
				clientToken, err := extractor(req)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}

				if !validateCSRFToken([]byte(token), clientToken) {
					http.Error(w, InvalidCSRFToken, http.StatusForbidden)
					return
				}
			}

			// Set CSRF cookie
			cookie := http.Cookie{
				Name:     config.CookieName,
				Value:    string(token),
				Path:     "/",
				MaxAge:   3600,
				HttpOnly: config.CookieHTTPOnly,
				Secure:   config.CookieSecure,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(time.Duration(config.CookieMaxAge) * time.Second),
			}

			if config.CookiePath != "" {
				cookie.Path = config.CookiePath
			}

			if config.CookieDomain != "" {
				cookie.Domain = config.CookieDomain
			}

			http.SetCookie(w, &cookie)

			//ctx.SetUserValue(config.ContextKey, token)

			req.Header.Set("Vary", "Cookie")

			next.ServeHTTP(w, req)
		})
	}

}

// csrfTokenFromForm returns a `csrfTokenExtractor` that extracts token from the
// provided request header.
func csrfTokenFromHeader(header string) csrfTokenExtractor {
	return func(req *http.Request) ([]byte, error) {
		srcToken := req.Header.Get(header)
		return copyCSRFTokenFromRequest([]byte(srcToken))
	}
}

// csrfTokenFromForm returns a `csrfTokenExtractor` that extracts token from the
// provided form parameter.
func csrfTokenFromForm(param string) csrfTokenExtractor {
	return func(req *http.Request) ([]byte, error) {
		srcToken := req.FormValue(param)
		return copyCSRFTokenFromRequest([]byte(srcToken))
	}
}

// csrfTokenFromQuery returns a `csrfTokenExtractor` that extracts token from the
// provided query parameter.
func csrfTokenFromQuery(param string) csrfTokenExtractor {
	return func(req *http.Request) ([]byte, error) {
		srcToken := req.URL.Query().Get(param)
		return copyCSRFTokenFromRequest([]byte(srcToken))
	}
}

func validateCSRFToken(token, clientToken []byte) bool {
	return subtle.ConstantTimeCompare(token, clientToken) == 1
}

func copyCSRFTokenFromRequest(srcToken []byte) ([]byte, error) {
	var dstToken []byte
	dstToken = append(dstToken, srcToken...)
	if sliceIsEmpty(dstToken) {
		return nil, errors.New(CSRFTokenNotFound)
	}
	return dstToken, nil
}

func sliceIsEmpty(slice []byte) bool {
	return len(slice) == 0
}

// https://tip.golang.org/doc/go1.19#:~:text=Read%20no%20longer%20buffers%20random%20data%20obtained%20from%20the%20operating%20system%20between%20calls
var randomReaderPool = sync.Pool{New: func() interface{} {
	return bufio.NewReader(rand.Reader)
}}

const randomStringCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const randomStringCharsetLen = 52 // len(randomStringCharset)
const randomStringMaxByte = 255 - (256 % randomStringCharsetLen)

func randomString(length uint8) string {
	reader := randomReaderPool.Get().(*bufio.Reader)
	defer randomReaderPool.Put(reader)

	b := make([]byte, length)
	r := make([]byte, length+(length/4)) // perf: avoid read from rand.Reader many times
	var i uint8 = 0

	// security note:
	// we can't just simply do b[i]=randomStringCharset[rb%len(randomStringCharset)],
	// len(len(randomStringCharset)) is 52, and rb is [0, 255], 256 = 52 * 4 + 48.
	// make the first 48 characters more possibly to be generated then others.
	// So we have to skip bytes when rb > randomStringMaxByte

	for {
		_, err := io.ReadFull(reader, r)
		if err != nil {
			panic("unexpected error happened when reading from bufio.NewReader(crypto/rand.Reader)")
		}
		for _, rb := range r {
			if rb > randomStringMaxByte {
				// Skip this number to avoid bias.
				continue
			}
			b[i] = randomStringCharset[rb%randomStringCharsetLen]
			i++
			if i == length {
				return string(b)
			}
		}
	}
}
