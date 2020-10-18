// Package idaas implements the OAuth2 protocol for authenticating users through idaas.
// This package can be used as a reference implementation of an OAuth2 provider for Goth.
package idaas

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	"fmt"
	"github.com/chenarmy/goth"
	"golang.org/x/oauth2"
)

var (
	issuerURL  = "https://magicmall.cloudidaas.com/open/oauth2/authorize"
	authURL    = "https://magicmall.cloudidaas.com/open/oauth2/authorize"
	tokenURL   = "https://api.open.cloudidaas.com/oauth2/v1/token"
	profileURL = "https://api.open.cloudidaas.com/oauth2/v1/userinfo"
)

// Provider is the implementation of `goth.Provider` for accessing idaas.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	issuerURL    string
	profileURL   string
}

// New creates a new Idaas provider and sets up important connection details.
// You should always call `idaas.New` to get a new provider.  Never try to
// create one manually.
func New(clientID, secret, orgURL, callbackURL string, scopes ...string) *Provider {
	issuerURL := orgURL
	authURL := issuerURL + "/open/oauth2/authorize"
	tokenURL := issuerURL + "/oauth2/v1/token"
	profileURL := issuerURL + "/oauth2/v1/userinfo"
	return NewCustomisedURL(clientID, secret, callbackURL, authURL, tokenURL, issuerURL, profileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientID, secret, callbackURL, authURL, tokenURL, issuerURL, profileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientID,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "idaas",
		issuerURL:    issuerURL,
		profileURL:   profileURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the idaas package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks idaas for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

// FetchUser will go to idaas and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
		UserID:       sess.UserID,
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		return user, err
	}
	req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	response, err := p.Client().Do(req)
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return user, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}

	err = userFromReader(bytes.NewReader(bits), &user)

	return user, err
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

func userFromReader(r io.Reader, user *goth.User) error {
	u := struct {
		Username string `json:"user_id"`
	}{}

	err := json.NewDecoder(r).Decode(&u)
	if err != nil {
		return err
	}

	rd := make(map[string]interface{})
	rd["Username"] = u.Username

	user.UserID = u.Username

	user.RawData = rd

	return nil
}

//RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

//RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}
