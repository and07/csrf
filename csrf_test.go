package csrf

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func startServerForHandler(t *testing.T, h http.Handler, port int) io.Closer {
	ln, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatalf("cannot start tcp server on port %d: %s", port, err)
	}
	go http.Serve(ln, h)
	return ln
}

func handleStatusOK(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
}

func testRequestToHandler(
	t *testing.T,
	h http.Handler,
	method string,
	port int,
	testName string,
	expectedStatus int,
) *http.Response {

	ln := startServerForHandler(t, h, port)
	defer ln.Close()

	req, err := http.NewRequest(method, fmt.Sprintf("http://localhost:%d/", port), nil)
	assert.Nil(t, err, fmt.Sprintf("%s test should be able to create a request", testName))

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(t, err, "Sending the request must not return an error")
	assert.NotNil(t, resp, "Request response must not be nil")
	assert.Equal(t, expectedStatus, resp.StatusCode, fmt.Sprintf("%s test should return a %d status", testName, expectedStatus))
	if err != nil {
		panic(err)
	}
	return resp
}

func mapCookies(cookies []*http.Cookie) map[string]interface{} {
	cookiesMap := make(map[string]interface{}, len(cookies))
	for _, cookie := range cookies {
		cookieValues := strings.Split(fmt.Sprintf("%v", cookie), ";")
		for _, cookieValue := range cookieValues {
			cookieParts := strings.Split(strings.TrimSpace(cookieValue), "=")
			cookiesMap[cookieParts[0]] = cookieParts[1]
		}
	}
	return cookiesMap
}

func TestDefaultUsage(t *testing.T) {

	mux := http.NewServeMux()
	var finalHandler = http.HandlerFunc(handleStatusOK)
	mux.Handle("/", CSRF(finalHandler))

	resp := testRequestToHandler(t, mux, "GET", 8080, "Default Usage", http.StatusOK)

	cookiesMap := mapCookies(resp.Cookies())

	t.Logf("%#v", resp.Cookies())
	assert.Len(t, cookiesMap[DefaultCSRFConfig.CookieName], int(DefaultCSRFConfig.TokenLength), "Cookie token must have length equals to config")
}

func TestWithEmptyConfig(t *testing.T) {

	mux := http.NewServeMux()
	var finalHandler = http.HandlerFunc(handleStatusOK)
	mux.Handle("/", finalHandler)

	c := CSRFConfig{}
	h := CSRFWithConfig(c)(mux)
	resp := testRequestToHandler(t, h, "GET", 8081, "Empty Config", http.StatusOK)
	cookiesMap := mapCookies(resp.Cookies())
	assert.Len(t, cookiesMap[DefaultCSRFConfig.CookieName], int(DefaultCSRFConfig.TokenLength), "Cookie token must have length equals to config")
}

func TestEmptyToken(t *testing.T) {
	mux := http.NewServeMux()
	var finalHandler = http.HandlerFunc(handleStatusOK)
	mux.Handle("/", finalHandler)

	h := CSRF(mux)
	testRequestToHandler(t, h, "POST", 8082, "Header Token Lookup", http.StatusBadRequest)
}

func TestInvalidToken(t *testing.T) {

	mux := http.NewServeMux()
	var finalHandler = http.HandlerFunc(handleStatusOK)
	mux.Handle("/", finalHandler)
	h := CSRF(mux)

	ln := startServerForHandler(t, h, 8083)
	defer ln.Close()
	url := fmt.Sprintf("http://localhost:%d", 8083)
	invalidCsrf := randomString(32)
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Add(DefaultTokenLookup, string(invalidCsrf))
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(t, err, "Sending the request must not return an error")
	assert.NotNil(t, resp, "Request response must not be nil")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "Invalid Token test should return a forbidden status")
}

func TestFormExtractor(t *testing.T) {
	c := DefaultCSRFConfig
	c.TokenLookup = "form:csrfToken"

	mux := http.NewServeMux()
	var finalHandler = http.HandlerFunc(handleStatusOK)
	mux.Handle("/", finalHandler)

	h := CSRFWithConfig(c)(mux)
	testPort := 8084
	ln := startServerForHandler(t, h, testPort)
	defer ln.Close()
	addr := fmt.Sprintf("http://localhost:%d", testPort)
	req, _ := http.NewRequest("GET", addr, nil)
	resp, _ := http.DefaultClient.Do(req)
	cookies := resp.Cookies()
	cookiesMap := mapCookies(cookies)
	csrf := cookiesMap[DefaultCSRFConfig.CookieName].(string)
	form := url.Values{}
	form.Add("csrfToken", csrf)

	t.Log(csrf)

	req, _ = http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(t, err, "Sending the request must not return an error")
	assert.NotNil(t, resp, "Request response must not be nil")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Valid Token test should return an Ok status")
}

func TestQueryExtractor(t *testing.T) {
	c := DefaultCSRFConfig
	c.TokenLookup = "query:csrfToken"

	mux := http.NewServeMux()
	var finalHandler = http.HandlerFunc(handleStatusOK)
	mux.Handle("/", finalHandler)

	h := CSRFWithConfig(c)(mux)
	testPort := 8085
	ln := startServerForHandler(t, h, testPort)
	defer ln.Close()
	addr := fmt.Sprintf("http://localhost:%d", testPort)
	req, _ := http.NewRequest("GET", addr, nil)
	resp, _ := http.DefaultClient.Do(req)
	cookies := resp.Cookies()
	cookiesMap := mapCookies(cookies)
	csrf := cookiesMap[DefaultCSRFConfig.CookieName].(string)
	addrWithQuery := fmt.Sprintf("http://localhost:%d?csrfToken=%s", testPort, csrf)
	req, _ = http.NewRequest("POST", addrWithQuery, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(t, err, "Sending the request must not return an error")
	assert.NotNil(t, resp, "Request response must not be nil")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Valid Token test should return an Ok status")
}

func TestValidToken(t *testing.T) {
	c := DefaultCSRFConfig
	c.CookiePath = "/valid"
	c.CookieDomain = "localhost"

	mux := http.NewServeMux()
	var finalHandler = http.HandlerFunc(handleStatusOK)
	mux.Handle("/", finalHandler)

	h := CSRFWithConfig(c)(mux)
	testPort := 8086
	ln := startServerForHandler(t, h, testPort)
	defer ln.Close()
	url := fmt.Sprintf("http://localhost:%d/valid", testPort)
	req, _ := http.NewRequest("GET", url, nil)
	resp, _ := http.DefaultClient.Do(req)
	cookies := resp.Cookies()
	cookiesMap := mapCookies(cookies)
	csrf := cookiesMap[DefaultCSRFConfig.CookieName].(string)
	req, _ = http.NewRequest("POST", url, nil)
	req.Header.Add(DefaultTokenLookup, csrf)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(t, err, "Sending the request must not return an error")
	assert.NotNil(t, resp, "Request response must not be nil")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Valid Token test should return an Ok status")
	assert.Equal(t, c.CookiePath, cookiesMap["Path"], "Valid Token test should have same cookie path")
	assert.Equal(t, c.CookieDomain, cookiesMap["Domain"], "Valid Token test should have same cookie domain")
}
