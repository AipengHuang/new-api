package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func init() {
	Register("oidc", &OIDCProvider{})
}

// OIDCProvider implements OAuth for OIDC
type OIDCProvider struct{}

type oidcFlowContextKey int

const OIDCOAuthFlowContextKey oidcFlowContextKey = 0

// OIDCOAuthFlow keeps the proof and its original configuration server-side.
type OIDCOAuthFlow struct {
	CodeVerifier          string   `json:"code_verifier"`
	ClientID              string   `json:"client_id"`
	ClientSecretHash      [32]byte `json:"client_secret_hash"`
	RedirectURI           string   `json:"redirect_uri"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"user_info_endpoint"`
	BrowserTokenHash      [32]byte `json:"browser_token_hash"`
}

func NewOIDCOAuthFlow(browserToken string) (*OIDCOAuthFlow, error) {
	settings := system_setting.GetOIDCSettings()
	redirectURI := strings.TrimRight(system_setting.ServerAddress, "/") + "/oauth/oidc"
	if !settings.Enabled || settings.ClientId == "" || settings.ClientSecret == "" || browserToken == "" {
		return nil, model.ErrAuthFlowInvalid
	}
	for _, endpoint := range []string{settings.AuthorizationEndpoint, settings.TokenEndpoint, settings.UserInfoEndpoint, redirectURI} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Scheme != "https" {
			return nil, model.ErrAuthFlowInvalid
		}
	}
	return &OIDCOAuthFlow{
		CodeVerifier: oauth2.GenerateVerifier(), ClientID: settings.ClientId,
		ClientSecretHash: sha256.Sum256([]byte(settings.ClientSecret)), RedirectURI: redirectURI,
		AuthorizationEndpoint: settings.AuthorizationEndpoint, TokenEndpoint: settings.TokenEndpoint,
		UserInfoEndpoint: settings.UserInfoEndpoint, BrowserTokenHash: sha256.Sum256([]byte(browserToken)),
	}, nil
}

func (flow *OIDCOAuthFlow) AuthorizationURL(state string) (string, error) {
	endpoint, err := url.Parse(flow.AuthorizationEndpoint)
	if err != nil {
		return "", model.ErrAuthFlowInvalid
	}
	query := endpoint.Query()
	query.Del("client_secret")
	query.Del("code_verifier")
	query.Set("client_id", flow.ClientID)
	query.Set("redirect_uri", flow.RedirectURI)
	query.Set("response_type", "code")
	query.Set("scope", "openid profile email")
	query.Set("state", state)
	query.Set("code_challenge", oauth2.S256ChallengeFromVerifier(flow.CodeVerifier))
	query.Set("code_challenge_method", "S256")
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func (flow *OIDCOAuthFlow) MatchesBrowser(token string) bool {
	if token == "" {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(hash[:], flow.BrowserTokenHash[:]) == 1
}

func (flow *OIDCOAuthFlow) MatchesConfiguration() bool {
	if flow == nil {
		return false
	}
	verifier, err := base64.RawURLEncoding.DecodeString(flow.CodeVerifier)
	settings := system_setting.GetOIDCSettings()
	return err == nil && len(verifier) == 32 && settings.Enabled &&
		flow.ClientID == settings.ClientId && flow.ClientSecretHash == sha256.Sum256([]byte(settings.ClientSecret)) &&
		flow.RedirectURI == strings.TrimRight(system_setting.ServerAddress, "/")+"/oauth/oidc" &&
		flow.AuthorizationEndpoint == settings.AuthorizationEndpoint && flow.TokenEndpoint == settings.TokenEndpoint &&
		flow.UserInfoEndpoint == settings.UserInfoEndpoint
}

type oidcOAuthResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type oidcUser struct {
	OpenID            string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Picture           string `json:"picture"`
}

func (p *OIDCProvider) GetName() string {
	return system_setting.GetOIDCSettings().GetEffectiveDisplayName()
}

func (p *OIDCProvider) IsEnabled() bool {
	return system_setting.GetOIDCSettings().Enabled
}

func (p *OIDCProvider) ExchangeToken(ctx context.Context, code string, _ *gin.Context) (*OAuthToken, error) {
	flow, ok := ctx.Value(OIDCOAuthFlowContextKey).(*OIDCOAuthFlow)
	if !ok || !flow.MatchesConfiguration() {
		return nil, model.ErrAuthFlowInvalid
	}
	if code == "" {
		return nil, NewOAuthError(common.NewMessage(msgInvalidCode))
	}

	settings := system_setting.GetOIDCSettings()
	redirectUri := flow.RedirectURI
	values := url.Values{}
	values.Set("client_id", settings.ClientId)
	values.Set("client_secret", settings.ClientSecret)
	values.Set("code", code)
	values.Set("grant_type", "authorization_code")
	values.Set("redirect_uri", redirectUri)
	values.Set("code_verifier", flow.CodeVerifier)

	logger.LogDebug(ctx, "[OAuth-OIDC] ExchangeToken: token_endpoint=%s, redirect_uri=%s", settings.TokenEndpoint, redirectUri)

	req, err := http.NewRequestWithContext(ctx, "POST", settings.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Do(req)
	if err != nil {
		logger.LogError(ctx, common.LogText("[OAuth-OIDC] ExchangeToken error: %s", err.Error()))
		return nil, NewOAuthErrorWithRaw(common.NewMessage(msgConnectFailed, map[string]any{"provider": "OIDC"}), err.Error())
	}
	defer res.Body.Close()

	logger.LogDebug(ctx, "[OAuth-OIDC] ExchangeToken response status: %d", res.StatusCode)
	if res.StatusCode != http.StatusOK {
		return nil, NewOAuthError(common.NewMessage(msgTokenFailed, map[string]any{"provider": "OIDC"}))
	}

	var oidcResponse oidcOAuthResponse
	err = common.DecodeJson(res.Body, &oidcResponse)
	if err != nil {
		logger.LogError(ctx, common.LogText("[OAuth-OIDC] ExchangeToken decode error: %s", err.Error()))
		return nil, err
	}

	if oidcResponse.AccessToken == "" {
		logger.LogError(ctx, common.LogText("[OAuth-OIDC] ExchangeToken failed: empty access token"))
		return nil, NewOAuthError(common.NewMessage(msgTokenFailed, map[string]any{"provider": "OIDC"}))
	}

	logger.LogDebug(ctx, "[OAuth-OIDC] ExchangeToken success: scope=%s", oidcResponse.Scope)

	return &OAuthToken{
		AccessToken:  oidcResponse.AccessToken,
		TokenType:    oidcResponse.TokenType,
		RefreshToken: oidcResponse.RefreshToken,
		ExpiresIn:    oidcResponse.ExpiresIn,
		Scope:        oidcResponse.Scope,
		IDToken:      oidcResponse.IDToken,
	}, nil
}

func (p *OIDCProvider) GetUserInfo(ctx context.Context, token *OAuthToken) (*OAuthUser, error) {
	flow, ok := ctx.Value(OIDCOAuthFlowContextKey).(*OIDCOAuthFlow)
	if !ok || !flow.MatchesConfiguration() {
		return nil, model.ErrAuthFlowInvalid
	}

	logger.LogDebug(ctx, "[OAuth-OIDC] GetUserInfo: userinfo_endpoint=%s", flow.UserInfoEndpoint)

	req, err := http.NewRequestWithContext(ctx, "GET", flow.UserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Do(req)
	if err != nil {
		logger.LogError(ctx, common.LogText("[OAuth-OIDC] GetUserInfo error: %s", err.Error()))
		return nil, NewOAuthErrorWithRaw(common.NewMessage(msgConnectFailed, map[string]any{"provider": "OIDC"}), err.Error())
	}
	defer res.Body.Close()

	logger.LogDebug(ctx, "[OAuth-OIDC] GetUserInfo response status: %d", res.StatusCode)

	if res.StatusCode != http.StatusOK {
		logger.LogError(ctx, common.LogText("[OAuth-OIDC] GetUserInfo failed: status=%d", res.StatusCode))
		return nil, NewOAuthError(common.NewMessage(msgGetUserFailed))
	}

	var oidcUser oidcUser
	err = common.DecodeJson(res.Body, &oidcUser)
	if err != nil {
		logger.LogError(ctx, common.LogText("[OAuth-OIDC] GetUserInfo decode error: %s", err.Error()))
		return nil, err
	}

	if oidcUser.OpenID == "" || oidcUser.Email == "" {
		logger.LogError(ctx, common.LogText("[OAuth-OIDC] GetUserInfo failed: empty fields (sub=%s, email=%s)", oidcUser.OpenID, oidcUser.Email))
		return nil, NewOAuthError(common.NewMessage(msgUserInfoEmpty, map[string]any{"provider": "OIDC"}))
	}

	logger.LogDebug(ctx, "[OAuth-OIDC] GetUserInfo success: sub=%s, username=%s, name=%s, email=%s", oidcUser.OpenID, oidcUser.PreferredUsername, oidcUser.Name, oidcUser.Email)

	return &OAuthUser{
		ProviderUserID: oidcUser.OpenID,
		Username:       oidcUser.PreferredUsername,
		DisplayName:    oidcUser.Name,
		Email:          oidcUser.Email,
	}, nil
}

func (p *OIDCProvider) IsUserIDTaken(providerUserID string) bool {
	return model.IsOidcIdAlreadyTaken(providerUserID)
}

func (p *OIDCProvider) FillUserByProviderID(user *model.User, providerUserID string) error {
	user.OidcId = providerUserID
	return user.FillUserByOidcId()
}

func (p *OIDCProvider) SetProviderUserID(user *model.User, providerUserID string) {
	user.OidcId = providerUserID
}

func (p *OIDCProvider) GetProviderPrefix() string {
	return "oidc_"
}

// ProviderUserIDColumn returns the users-table column storing this provider's user ID.
func (p *OIDCProvider) ProviderUserIDColumn() string {
	return "oidc_id"
}
