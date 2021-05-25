package apiclient

import "time"

type ClientResponse struct {
	SiteId     string
	IpAddress  string
	MacAddress string
	DeviceName string
	Hostname   string
	Name       string
	LastSeen   time.Time
}