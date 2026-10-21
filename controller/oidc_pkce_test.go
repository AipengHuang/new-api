package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/oauth"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type oidcPKCEFixture struct {
	user      *model.User
	identity  service.AuthIdentity
	grants    map[string]string
	mutex     sync.Mutex
	exchanges atomic.Int32
}

func setupOIDCPKCETest(t *testing.T) *oidcPKCEFixture {
	t.Helper()
	user, identity := setupSecurityEnrollmentTest(t)
	previousSettings, previousAddress := *system_setting.GetOIDCSettings(), system_setting.ServerAddress
	t.Cleanup(func() {
		*system_setting.GetOIDCSettings() = previousSettings
		system_setting.ServerAddress = previousAddress
	})
	require.NoError(t, model.DB.Model(user).Updates(map[string]any{"email": "oidc@example.invalid", "oidc_id": "permanent-user", "quota": 12345}).Error)
	fixture := &oidcPKCEFixture{user: user, identity: identity, grants: map[string]string{}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mutex.Lock()
		defer fixture.mutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			fixture.exchanges.Add(1)
			if !assert.NoError(t, r.ParseForm()) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			challenge, ok := fixture.grants[r.Form.Get("code")]
			if !ok || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_id") != "oidc-client" ||
				r.Form.Get("client_secret") != "oidc-secret" || r.Form.Get("redirect_uri") != "https://example.com/oauth/oidc" ||
				r.Form.Get("code_verifier") == "" || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			delete(fixture.grants, r.Form.Get("code"))
			_, _ = w.Write([]byte(`{"access_token":"fixture-access-token","token_type":"Bearer"}`))
		case "/userinfo":
			assert.Equal(t, "Bearer fixture-access-token", r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"sub":"permanent-user","email":"oidc@example.invalid","name":"Original user"}`))
		default:
			t.Errorf("unexpected OIDC request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	previousTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	*system_setting.GetOIDCSettings() = system_setting.OIDCSettings{
		Enabled: true, ClientId: "oidc-client", ClientSecret: "oidc-secret",
		AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", UserInfoEndpoint: server.URL + "/userinfo",
	}
	system_setting.ServerAddress = "https://example.com"
	return fixture
}

func (fixture *oidcPKCEFixture) start(t *testing.T, intent string) (string, string, *http.Cookie) {
	t.Helper()
	proof, scope := "", ""
	if intent == "bind" {
		proof = issueSecurityEnrollmentProof(t, fixture.identity, service.VerificationOperation{Scope: service.VerificationScopeAccountBind, Context: []byte(`{"provider":"oidc"}`)}, service.VerificationMethodPassword)
	}
	if intent == "verify" {
		scope = "2fa.setup"
	}
	body, err := common.Marshal(oauthStateRequest{Provider: "oidc", Intent: intent, Scope: scope})
	require.NoError(t, err)
	response := securityEnrollmentRequest(http.MethodPost, "/api/oauth/state", string(body), proof, fixture.identity, GenerateOAuthCode)
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			State string `json:"flow_token"`
			URL   string `json:"authorization_url"`
		} `json:"data"`
	}
	require.NoError(t, common.Unmarshal(response.Body.Bytes(), &result))
	require.True(t, result.Success, response.Body.String())
	require.NotEmpty(t, result.Data.URL, "OIDC must return a server-built PKCE authorization URL")
	authorize, err := url.Parse(result.Data.URL)
	require.NoError(t, err)
	assert.Equal(t, "S256", authorize.Query().Get("code_challenge_method"))
	assert.Len(t, authorize.Query().Get("code_challenge"), 43)
	assert.Equal(t, result.Data.State, authorize.Query().Get("state"))
	assert.Equal(t, "openid profile email", authorize.Query().Get("scope"))
	assert.Empty(t, authorize.Query().Get("code_verifier"))
	assert.NotContains(t, response.Body.String(), "oidc-secret")
	cookies := response.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.True(t, cookies[0].Secure)
	assert.True(t, cookies[0].HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)
	assert.True(t, strings.HasPrefix(cookies[0].Name, "__Host-"))
	assert.Equal(t, "/", cookies[0].Path)
	assert.Empty(t, cookies[0].Domain)
	assert.Equal(t, int(oauthAuthFlowTTL.Seconds()), cookies[0].MaxAge)
	flow, err := model.GetAuthFlow(result.Data.State, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeOAuth, Provider: "oidc"})
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, common.UnmarshalJsonStr(flow.Payload, &payload))
	verifier := payload["oidc"].(map[string]any)["code_verifier"].(string)
	assert.NotContains(t, response.Body.String(), verifier)
	assert.NotContains(t, flow.Payload, cookies[0].Value)
	assert.Equal(t, authorize.Query().Get("code_challenge"), oauth2.S256ChallengeFromVerifier(verifier))
	code := "code-" + result.Data.State
	fixture.mutex.Lock()
	fixture.grants[code] = authorize.Query().Get("code_challenge")
	fixture.mutex.Unlock()
	return result.Data.State, code, cookies[0]
}

func oidcPKCECallback(state, query string, cookie *http.Cookie, identity service.AuthIdentity) *httptest.ResponseRecorder {
	return securityEnrollmentRequest(http.MethodGet, "/api/oauth/oidc?state="+url.QueryEscape(state)+query, "", "", identity, func(c *gin.Context) {
		c.Params = gin.Params{{Key: "provider", Value: "oidc"}}
		if cookie != nil {
			c.Request.AddCookie(cookie)
		}
		HandleOAuth(c)
	})
}

func TestOIDCPKCELoginPreservesAccountAndRejectsReplay(t *testing.T) {
	fixture := setupOIDCPKCETest(t)
	before, err := model.GetUserById(fixture.user.Id, true)
	require.NoError(t, err)
	state, code, cookie := fixture.start(t, "login")
	otherState, _, otherCookie := fixture.start(t, "login")
	assert.NotEqual(t, state, otherState)
	assert.NotEqual(t, cookie.Name, otherCookie.Name)
	assert.NotEqual(t, cookie.Value, otherCookie.Value)
	firstFlow, err := model.GetAuthFlow(state, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeOAuth, Provider: "oidc"})
	require.NoError(t, err)
	secondFlow, err := model.GetAuthFlow(otherState, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeOAuth, Provider: "oidc"})
	require.NoError(t, err)
	var firstPayload, secondPayload oauthFlowPayload
	require.NoError(t, common.UnmarshalJsonStr(firstFlow.Payload, &firstPayload))
	require.NoError(t, common.UnmarshalJsonStr(secondFlow.Payload, &secondPayload))
	assert.NotEqual(t, firstPayload.OIDC.CodeVerifier, secondPayload.OIDC.CodeVerifier)
	response := oidcPKCECallback(state, "&code="+url.QueryEscape(code), cookie, service.AuthIdentity{})
	assert.Contains(t, response.Body.String(), `"success":true`)
	assert.Contains(t, response.Body.String(), fmt.Sprintf(`"id":%d`, fixture.user.Id))
	assert.EqualValues(t, 1, fixture.exchanges.Load())
	after, err := model.GetUserById(fixture.user.Id, true)
	require.NoError(t, err)
	assert.Equal(t, before.Password, after.Password)
	assert.Equal(t, before.Quota, after.Quota)
	assert.Equal(t, before.Email, after.Email)
	assert.Equal(t, before.OidcId, after.OidcId)
	var count int64
	require.NoError(t, model.DB.Model(&model.User{}).Count(&count).Error)
	assert.EqualValues(t, 1, count)
	assert.Equal(t, http.StatusForbidden, oidcPKCECallback(state, "&code="+url.QueryEscape(code), cookie, service.AuthIdentity{}).Code)
	assert.EqualValues(t, 1, fixture.exchanges.Load())
}

func TestOIDCPKCERejectsInvalidFlowBeforeTokenExchange(t *testing.T) {
	for _, scenario := range []string{"no cookie", "wrong cookie", "other flow cookie", "expired", "missing flow", "missing verifier", "invalid verifier", "changed client", "changed secret", "changed endpoint", "changed userinfo", "changed redirect"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := setupOIDCPKCETest(t)
			state, code, cookie := fixture.start(t, "login")
			flow, err := model.GetAuthFlow(state, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeOAuth, Provider: "oidc"})
			require.NoError(t, err)
			switch scenario {
			case "no cookie":
				cookie = nil
			case "wrong cookie":
				cookie.Value = oauth2.GenerateVerifier()
			case "other flow cookie":
				_, _, cookie = fixture.start(t, "login")
			case "expired":
				require.NoError(t, model.DB.Model(flow).Update("expires_at", time.Now().Add(-time.Second)).Error)
			case "missing flow":
				require.NoError(t, model.DB.Model(flow).Update("payload", `{}`).Error)
			case "missing verifier", "invalid verifier":
				var payload map[string]any
				require.NoError(t, common.UnmarshalJsonStr(flow.Payload, &payload))
				payload["oidc"].(map[string]any)["code_verifier"] = ""
				if scenario == "invalid verifier" {
					payload["oidc"].(map[string]any)["code_verifier"] = strings.Repeat("!", 43)
				}
				body, err := common.Marshal(payload)
				require.NoError(t, err)
				require.NoError(t, model.DB.Model(flow).Update("payload", string(body)).Error)
			case "changed client":
				system_setting.GetOIDCSettings().ClientId = "replacement-client"
			case "changed secret":
				system_setting.GetOIDCSettings().ClientSecret = "replacement-secret"
			case "changed endpoint":
				system_setting.GetOIDCSettings().TokenEndpoint += "/replacement"
			case "changed userinfo":
				system_setting.GetOIDCSettings().UserInfoEndpoint += "/replacement"
			case "changed redirect":
				system_setting.ServerAddress = "https://different.example.com"
			}
			response := oidcPKCECallback(state, "&code="+url.QueryEscape(code), cookie, service.AuthIdentity{})
			assert.NotContains(t, response.Body.String(), `"success":true`)
			assert.Zero(t, fixture.exchanges.Load())
		})
	}
}

func TestOIDCPKCEWrongVerifierCannotFallBack(t *testing.T) {
	fixture := setupOIDCPKCETest(t)
	state, code, cookie := fixture.start(t, "login")
	flow, err := model.GetAuthFlow(state, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeOAuth, Provider: "oidc"})
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, common.UnmarshalJsonStr(flow.Payload, &payload))
	payload["oidc"].(map[string]any)["code_verifier"] = oauth2.GenerateVerifier()
	body, err := common.Marshal(payload)
	require.NoError(t, err)
	require.NoError(t, model.DB.Model(flow).Update("payload", string(body)).Error)
	response := oidcPKCECallback(state, "&code="+url.QueryEscape(code), cookie, service.AuthIdentity{})
	assert.NotContains(t, response.Body.String(), `"success":true`)
	assert.EqualValues(t, 1, fixture.exchanges.Load())
	assert.Equal(t, http.StatusForbidden, oidcPKCECallback(state, "&code="+url.QueryEscape(code), nil, service.AuthIdentity{}).Code)
	assert.EqualValues(t, 1, fixture.exchanges.Load())
}

func TestOIDCPKCEBindAndVerifyRemainSessionBound(t *testing.T) {
	for _, intent := range []string{"bind", "verify"} {
		t.Run(intent, func(t *testing.T) {
			fixture := setupOIDCPKCETest(t)
			if intent == "bind" {
				require.NoError(t, model.DB.Model(fixture.user).Update("oidc_id", "").Error)
			} else {
				require.NoError(t, model.DB.Model(fixture.user).Update("password", "").Error)
			}
			state, code, cookie := fixture.start(t, intent)
			other := fixture.identity
			other.SessionID = "different-session"
			assert.Equal(t, http.StatusForbidden, oidcPKCECallback(state, "&code="+url.QueryEscape(code), cookie, other).Code)
			assert.Zero(t, fixture.exchanges.Load())
			response := oidcPKCECallback(state, "&code="+url.QueryEscape(code), cookie, fixture.identity)
			assert.Contains(t, response.Body.String(), `"success":true`)
			assert.EqualValues(t, 1, fixture.exchanges.Load())
			assert.Equal(t, http.StatusForbidden, oidcPKCECallback(state, "&code="+url.QueryEscape(code), cookie, fixture.identity).Code)
		})
	}
}

func TestOIDCPKCEProviderCancellationConsumesFlowAndClearsCookie(t *testing.T) {
	fixture := setupOIDCPKCETest(t)
	state, _, cookie := fixture.start(t, "login")
	response := oidcPKCECallback(state, "&error=access_denied", cookie, service.AuthIdentity{})
	assert.NotContains(t, response.Body.String(), `"success":true`)
	assert.Zero(t, fixture.exchanges.Load())
	_, err := model.GetAuthFlow(state, model.AuthFlowMatch{Purpose: model.AuthFlowPurposeOAuth, Provider: "oidc"})
	assert.ErrorIs(t, err, model.ErrAuthFlowConsumed)
	cookies := response.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, cookie.Name, cookies[0].Name)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

func TestOIDCPKCERejectsHTTPConfiguration(t *testing.T) {
	setupOIDCPKCETest(t)
	system_setting.GetOIDCSettings().TokenEndpoint = "http://example.com/token"
	response := securityEnrollmentRequest(http.MethodPost, "/api/oauth/state", `{"provider":"oidc","intent":"login"}`, "", service.AuthIdentity{}, GenerateOAuthCode)
	assert.NotContains(t, response.Body.String(), `"success":true`)
	assert.Empty(t, response.Result().Cookies())
	var count int64
	require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("provider = ?", "oidc").Count(&count).Error)
	assert.Zero(t, count)
}

func TestOIDCPKCERequiresServerOwnedContext(t *testing.T) {
	setupOIDCPKCETest(t)
	provider := &oauth.OIDCProvider{}
	_, err := provider.ExchangeToken(context.Background(), "unbound-code", nil)
	assert.ErrorIs(t, err, model.ErrAuthFlowInvalid)
	_, err = provider.GetUserInfo(context.Background(), &oauth.OAuthToken{AccessToken: "unbound-token"})
	assert.ErrorIs(t, err, model.ErrAuthFlowInvalid)
}
