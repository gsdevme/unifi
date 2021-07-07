package unifi_test

import (
	"github.com/gsdevme/unifi/pkg/unifi"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupServer(handleAuth func(rw http.ResponseWriter)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.String() == "/api/auth/login" {
			handleAuth(rw)

			return
		}
	}))
}

func createAuthToken(token string) func(rw http.ResponseWriter) {
	return func(rw http.ResponseWriter) {
		http.SetCookie(rw, &http.Cookie{
			Name:  unifi.AuthCookieName,
			Value: token,
		})

		rw.WriteHeader(http.StatusOK)
	}
}

func TestClient(t *testing.T) {
	t.Run("test authentication", func(t *testing.T) {
		s := setupServer(createAuthToken("1337"))
		defer s.Close()

		client := unifi.NewHTTPClient(s.URL, unifi.WithCredentials("admin", "pass1337"))
		expected := "1337"
		was, err := client.GetAuthToken()

		if err != nil {
			t.Errorf("error recived from client: %s", err)
		}

		if was != expected {
			t.Errorf("authenication token expected to be %s, got %s", expected, was)
		}
	})

	t.Run("test invalid auth", func(t *testing.T) {
		s := setupServer(func(rw http.ResponseWriter) {
			rw.WriteHeader(http.StatusUnauthorized)
		})
		defer s.Close()

		client := unifi.NewHTTPClient(s.URL, unifi.WithCredentials("admin", "pass1337"))
		_, err := client.GetAuthToken()

		if err == nil {
			t.Errorf("error recived from client: %s", err)
		}
	})

	t.Run("test no cookie", func(t *testing.T) {
		s := setupServer(func(rw http.ResponseWriter) {
			rw.WriteHeader(http.StatusOK)
		})
		defer s.Close()

		client := unifi.NewHTTPClient(s.URL, unifi.WithCredentials("admin", "pass1337"))
		_, err := client.GetAuthToken()

		if err == nil {
			t.Errorf("error recived from client: %s", err)
		}
	})

	t.Run("get token from client func", func(t *testing.T) {
		client := unifi.NewHTTPClient("example.com", unifi.WithAuthToken("123-123"))
		was, err := client.GetAuthToken()
		expected := "123-123"

		if err != nil {
			t.Errorf("error recived from client: %s", err)
		}

		if was != expected {
			t.Errorf("authenication token expected to be %s, got %s", expected, was)
		}
	})
}
