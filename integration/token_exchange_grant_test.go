package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	goauth "golang.org/x/oauth2"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
)

func TestClientTokenExchangeFlow(t *testing.T) {
	for _, strategy := range []oauth2.AccessTokenStrategy{
		hmacStrategy,
	} {
		runClientTokenExchangeGrantTest(t, strategy)
	}
}

func runClientTokenExchangeGrantTest(t *testing.T, strategy oauth2.AccessTokenStrategy) {
	f := compose.Compose(new(compose.Config), fositeStore, strategy, nil, compose.OAuth2TokenExchangeFactory, compose.OAuth2TokenIntrospectionFactory, compose.OAuth2ClientCredentialsGrantFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	defer ts.Close()

	oauthClient := newOAuth2TokenExchangeClient(ts)
	subClient := newOAuth2AppClient(ts)

	var sub string

	for k, c := range []struct {
		description string
		setup       func()
		err         bool
		check       func(t *testing.T, r *http.Response)
		params      url.Values
	}{

		{
			description: "should pass: received access token with client_credentials grant_type",
			setup: func() {
				oauthClient.Scopes = []string{"fosite"}
				oauthClient.EndpointParams.Set("audience", "gateway")
				token, _ := subClient.Token(goauth.NoContext)
				sub = token.AccessToken
			},
			params: url.Values{
				"grant_type": {"client_credentials"},
			},
		},
		{
			description: "should fail because of  unauthorized_client",
			setup: func() {
				oauthClient.Scopes = []string{"wrong_scope"}
				oauthClient.ClientID = "wrong_client"
			},
			err:    true,
			params: url.Values{"grant_type": {"token-exchange"}},
		},

		{
			description: "should fail because of  subject_token_type is not provided",
			setup: func() {
				oauthClient.Scopes = []string{"fosite"}
			},
			err:    true,
			params: url.Values{"grant_type": {"token-exchange"}},
		},

		{
			description: "should fail because of ungranted scopes",
			setup: func() {
				oauthClient.Scopes = []string{"wrong_scope"}
			},
			params: url.Values{
				"grant_type":         {"token-exchange"},
				"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
				"audience":           {"service4"},
			},
			err: true,
		},

		{
			description: "should fail because of ungranted audience",
			setup: func() {
				oauthClient.Scopes = []string{"fosite"}
			},
			params: url.Values{
				"grant_type":         {"token-exchange"},
				"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
				"audience":           {"wrong_service"},
			},
			err: true,
		},

		{
			description: "should pass",
			setup: func() {
				oauthClient.Scopes = []string{"fosite"}
				oauthClient.ClientID = "gateway"
			},
			params: url.Values{
				"grant_type":         {"token-exchange"},
				"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
				"audience":           {"service2"},
			},
			check: func(t *testing.T, r *http.Response) {
				var client map[string]interface{}

				require.NoError(t, json.NewDecoder(r.Body).Decode(&client))

				currentClient := client["client"].(map[string]interface{})
				subjectTokenClient := client["subjectTokenClient"].(map[string]interface{})

				//Check current client's params
				assert.EqualValues(t, "gateway", currentClient["id"])
				assert.EqualValues(t, []interface{}{"service2"}, client["requestedAudience"])
				assert.EqualValues(t, []interface{}{"fosite"}, client["grantedScopes"])

				//granted Audience
				assert.EqualValues(t, []interface{}{"service2", "service3"}, currentClient["audience"])

				//Check subjectClient params
				assert.EqualValues(t, "my-client", subjectTokenClient["id"])
				assert.EqualValues(t, []interface{}{"https://www.ory.sh/api", "gateway"}, subjectTokenClient["audience"])
				assert.EqualValues(t, []interface{}{"fosite", "offline", "openid"}, subjectTokenClient["scopes"])

			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()

			oauthClient.EndpointParams = c.params
			oauthClient.EndpointParams.Set("subject_token", sub)
			token, err := oauthClient.Token(goauth.NoContext)

			httpClient := oauthClient.Client(goauth.NoContext)
			resp, err := httpClient.Get(ts.URL + "/info")

			if c.check != nil {
				c.check(t, resp)
			}

			require.Equal(t, c.err, err != nil, "(%d) %s\n%s\n%s", k, c.description, c.err, err)
			if !c.err {
				assert.NotEmpty(t, token.AccessToken, "(%d) %s\n%s", k, c.description, token)
			}
			t.Logf("Passed test case %d", k)
		})
	}
}
