package apiclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	UserAgent      = "golang-unifi"
	ContentType    = "application/json"
	AuthCookieName = "TOKEN"
)

type clientFunc func(c *client)

// WithCredentials configures the client to use the provided username/password
// to authenticate requests.
func WithCredentials(username, password string) clientFunc {
	return func(c *client) {
		c.username = username
		c.password = password
	}
}

// WithAuthToken configures the client to use the provided auth token
// to authenticate requests.
func WithAuthToken(token string) clientFunc {
	return func(c *client) {
		c.authToken = token
	}
}

// HTTPClientConfig provides the configuration for Unifi clients.
type HTTPClientConfig struct {
	Url      string
	IsSecure bool
	Port     int
}

// This should probably be exported.

type client struct {
	authToken string
	username  string
	password  string
	http      *http.Client
	config    *HTTPClientConfig
}

// NewHTTPClient creates a new Unifi client that accesses devices via HTTP and
// authenticates via the provided authentication option.
func NewHTTPClient(url string, auth clientFunc) Client {
	// This should probably return an error?
	if url == "" {
		return nil
	}
	c := &client{
		http: &http.Client{
			Transport: insecureTransport(),
			Timeout:   time.Second * 5,
		},
		config: &HTTPClientConfig{
			Url: url,
		},
	}
	// even better would be to make auth `opts...clientFunc` and apply all of
	// them.
	auth(c)
	return c
}

func (c client) GetAuthToken() (string, error) {
	if c.authToken != "" {
		return c.authToken, nil
	}

	body, err := json.Marshal(&authRequestBody{
		Username: c.username,
		Password: c.password,
		Remember: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth request body: %w", err)
	}

	requestURL := makeUrl(c.config.Url, AuthLoginUri)
	req, err := http.NewRequest(http.MethodPost, requestURL, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create a request for %q: %w", requestURL, err)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", ContentType)

	res, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get auth token from %q: %w", requestURL, err)
	}

	if res.StatusCode != http.StatusOK {
		return "", errors.New("authentication failed")
	}

	for _, cookie := range res.Cookies() {
		if cookie.Name == AuthCookieName {
			return cookie.Value, nil
		}
	}
	return "", errors.New("could not authenticate")
}

func (c client) GetActiveClients(siteId string) ([]ClientResponse, error) {
	requestURL := makeUrl(c.config.Url, fmt.Sprintf(ActiveClients, siteId))
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create a request for %q: %w", requestURL, err)
	}

	authToken, err := c.GetAuthToken()
	if err != nil {
		return nil, fmt.Errorf("getting active clients failed: %w", err)
	}

	var cookie = http.Cookie{
		Name:  AuthCookieName,
		Value: authToken,
	}

	req.AddCookie(&cookie)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", ContentType)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth token from %q: %w", requestURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// These should return errors that are identifiable as authentication
		// failures.
		return nil, errors.New("failed to get an authentication token")
	}

	var clientsJson ActiveClientsJson
	if err := json.NewDecoder(resp.Body).Decode(&clientsJson); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	var clients []ClientResponse
	for _, client := range clientsJson.Data {
		clients = append(clients, ClientResponse{
			SiteId:     client.SiteID,
			IpAddress:  client.IP,
			MacAddress: client.Mac,
			DeviceName: client.DeviceName,
			Hostname:   client.Hostname,
			Name:       client.Name,
			LastSeen:   time.Unix(int64(client.LastSeen), 0),
		})
	}

	return clients, nil
	// https://172.16.16.1/proxy/network/api/s/default/stat/sta
}

func insecureTransport() *http.Transport {
	transport := &(*http.DefaultTransport.(*http.Transport))
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return transport
}
