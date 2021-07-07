package unifi_test

import (
	"github.com/gsdevme/unifi/pkg/unifi"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSomething(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.String() != "/api/auth/login" && req.URL.String() != "/proxy/network/api/s/wibble/stat/sta" {
			t.Error("path is expected to be login or stat but received " + req.URL.String())
		}

		if req.URL.String() == "/api/auth/login" {
			if req.Method != http.MethodPost {
				t.Error("Request should be a POST")
			}

			http.SetCookie(rw, &http.Cookie{
				Name:       unifi.AuthCookieName,
				Value:      "an-amazing-token",
			})

			return
		}

		if req.URL.String() == "/proxy/network/api/s/wibble/stat/sta" {
			if req.Method != http.MethodGet {
				t.Error("Request should be a GET")
			}

			cookie, err := req.Cookie(unifi.AuthCookieName)

			if err != nil {
				t.Error("")

				return
			}

			if cookie.Value != "an-amazing-token" {
				t.Error("Cookie token not set as expected")
			}

			return
		}

		t.Error("blah")
	}))

	defer server.Close()

	c := unifi.NewHTTPClient(server.URL, unifi.WithCredentials("admin", "pass1337"))
	_, err := c.GetActiveClients("wibble")

	if err == nil {
		t.Error("get active clients should not return an error")

		return
	}
}