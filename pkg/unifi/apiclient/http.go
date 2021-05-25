package apiclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

const UserAgent = "golang-unifi"
const ContentType = "application/json"
const AuthCookieName = "TOKEN"

type HttpClientConfig struct {
	Url      string
	IsSecure bool
	Port     int
}

type client struct {
	authToken string
	username  string
	password  string
	http      *http.Client
	config    *HttpClientConfig
}

func NewHttpClient(url string, username string, password string) Client {
	customTransport := &(*http.DefaultTransport.(*http.Transport))
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if len(url) <= 0 {
		return nil
	}

	return &client{
		http: &http.Client{
			Transport: customTransport,
			Timeout:   time.Second * 5,
		},
		username:  username,
		password:  password,
		authToken: "",
		config: &HttpClientConfig{
			Url: url,
		},
	}
}

func NewHttpClientWithToken(url string, token string) Client {
	customTransport := &(*http.DefaultTransport.(*http.Transport))
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if len(url) <= 0 {
		return nil
	}

	return &client{
		http: &http.Client{
			Transport: customTransport,
			Timeout:   time.Second * 5,
		},
		config: &HttpClientConfig{
			Url: url,
		},
	}
}

func (c client) GetAuthToken() (string, error) {
	if len(c.authToken) > 0 {
		return c.authToken, nil
	}

	body, _ := json.Marshal(&authRequestBody{
		Username: c.username,
		Password: c.password,
		Remember: true,
	})

	req, err := http.NewRequest(http.MethodPost, makeUrl(c.config.Url, AuthLoginUri), bytes.NewBuffer(body))

	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", ContentType)

	res, getErr := c.http.Do(req)

	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.StatusCode != 200 {
		return "", errors.New("authentication failed")
	}

	for _, cookie := range res.Cookies() {
		if cookie.Name == AuthCookieName {
			return cookie.Value, nil
		}
	}

	return "", errors.New("could not authenticate")
}

func (c client) GetActiveClients(siteId string) []ClientResponse {
	var authToken string
	req, err := http.NewRequest(http.MethodGet, makeUrl(c.config.Url, fmt.Sprintf(ActiveClients, siteId)), nil)

	if err != nil {
		panic(err.Error())
	}

	authToken, err = c.GetAuthToken()

	if err != nil {
		panic(err.Error())
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
		log.Fatal(err)
	}

	if resp.StatusCode != 200 {
		panic(resp.StatusCode)
	}

	var clientsJson ActiveClientsJson

	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&clientsJson); err != nil {
		panic(err.Error())
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

	return clients

	// https://172.16.16.1/proxy/network/api/s/default/stat/sta
}
