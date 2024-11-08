package apishodan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const URL = "https://api.shodan.io"
const URLDOMAIN = "https://api.shodan.io/dns/domain/"

type API struct {
	apiKey string
}

type JsonData struct {
	QueryCredits int    `json:"query_credits"`
	ScanCredits  int    `json:"scan_credits"`
	Telnet       bool   `json:"telnet"`
	Plan         string `json:"plan"`
	HTTPS        bool   `json:"https"`
	Unlocked     bool   `json:"unlocked"`
}

type JsonSubDomain struct {
	Domain     string      `json:"domain,omitempty"`
	Tags       []string    `json:"tags,omitempty"`
	Data       []SubDomain `json:"data,omitempty"`
	SubDomains []string    `json:"subdomains,omitempty"`
}

type SubDomain struct {
	SubD     string `json:"subdomain,omitempty"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
}

func New(key string) *API {
	return &API{apiKey: key}
}

func (s *API) InfoAccount() (*JsonData, error) {
    res, err := http.Get(fmt.Sprintf("%s/api-info?key=%s", URL, s.apiKey))
    if err != nil {
        return nil, fmt.Errorf("failed to make request ( Info Account Shodan ): %v", err)
    }
    defer res.Body.Close()

    if res.StatusCode == http.StatusUnauthorized {
        return nil, fmt.Errorf("invalid API key (HTTP 401)")
    }

    if res.StatusCode == http.StatusForbidden {
        return nil, fmt.Errorf("API key has hit its limit (HTTP 403)")
    }

    if res.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
    }

    body, err := io.ReadAll(res.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %v", err)
    }

    var ret JsonData
    if err := json.Unmarshal(body, &ret); err != nil {
        return nil, fmt.Errorf("failed to decode JSON response: %v", err)
    }

    return &ret, nil
}

func (s *API) GetSubdomain(domain string) (*JsonSubDomain, error) {

	url := URLDOMAIN + domain + "?key=" + s.apiKey
	res, err := http.Get(url)

	if err != nil {
		fmt.Println(">> Something went wrong")
		panic(err)
	}
	defer res.Body.Close()

	var sub JsonSubDomain

	if err := json.NewDecoder(res.Body).Decode(&sub); err != nil {
		return nil, err
	}

	return &sub, nil

}
