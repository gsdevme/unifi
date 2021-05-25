package apiclient

import (
	"fmt"
)

const (
	AuthLoginUri  = "api/auth/login"
	ActiveClients = "proxy/network/api/s/%s/stat/sta"
)

type authRequestBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Remember bool   `json:"remember,omitempty"`
}

type Client interface {
	GetAuthToken() (string, error)
	GetActiveClients(siteId string) []ClientResponse
}

func makeUrl(url string, uri string) string {
	//url := strings.TrimFunc(url, func(v rune) bool {
	//	return v
	//})

	// TODO support non-UDM devices

	return fmt.Sprintf("%s/%s", url, uri)
}
