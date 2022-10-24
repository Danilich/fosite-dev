package rfc8693

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestTokenExchange_HandleTokenEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	areq := internal.NewMockTokenExchangeAccessRequester(ctrl)
	delegatedAreq := internal.NewMockAccessRequester(ctrl)
	coreStore := internal.NewMockCoreStorage(ctrl)
	coreChgen := internal.NewMockCoreStrategy(ctrl)
	storage := internal.NewMockStorage(ctrl)
	defer ctrl.Finish()

	h := Handler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: chgen,
			AccessTokenLifespan: time.Hour,
		},
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		CoreStorage:              coreStore,
		CoreStrategy:             coreChgen,
		Store:                    storage,
	}
	for k, c := range []struct {
		description string
		mock        func()
		req         *http.Request
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{""})
			},
		},
		{
			description: "should fail because subject_token not set",
			expectErr:   fosite.ErrInvalidRequest.WithHint("Required parameter subject_token is missing."),
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"token-exchange"},
					Audience:   []string{"https://www.ory.sh/api"},
				})
				query, _ := url.ParseQuery("")
				areq.EXPECT().GetRequestForm().Return(query)
			},
		},
		{
			description: "should fail because subject_token_type not set",
			expectErr:   fosite.ErrInvalidRequest.WithHint("Parameter 'subject_token_type' must be set"),
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"token-exchange"})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					GrantTypes: fosite.Arguments{"token-exchange"},
					Audience:   []string{"https://www.ory.sh/api"},
				})
				query, _ := url.ParseQuery("subject_token=ABCD.1234")
				areq.EXPECT().GetRequestForm().Return(query)
			},
		},
		{
			description: "should fail because client cannot exchange its own token",
			expectErr:   fosite.ErrRequestForbidden.WithHint("Clients are not allowed to perform a token exchange on their own tokens"),
			mock: func() {
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"token-exchange"})
				query, _ := url.ParseQuery("subject_token=ABCD.1234&subject_token_type=urn:ietf:params:oauth:token-type:access_token")
				areq.EXPECT().GetRequestForm().Return(query)
				exchangeClient := &fosite.DefaultClient{
					ID:         "exchange-client",
					GrantTypes: fosite.Arguments{"token-exchange"},
					Audience:   []string{"https://www.ory.sh/api"},
				}
				areq.EXPECT().GetClient().Return(exchangeClient)
				areq.EXPECT().GetSession()
				coreChgen.EXPECT().AccessTokenSignature("ABCD.1234").Return("1234")
				coreStore.EXPECT().GetAccessTokenSession(nil, "1234", nil).Return(delegatedAreq, nil)
				coreChgen.EXPECT().ValidateAccessToken(nil, delegatedAreq, "ABCD.1234").Return(nil)

				delegatedAreq.EXPECT().GetSubjectTokenClient().Times(2).Return(exchangeClient)
			},
		},
		{
			description: "should pass",
			mock: func() {
				session := new(fosite.DefaultSession)
				areq.EXPECT().GetSession().AnyTimes().Return(session)
				areq.EXPECT().GetGrantTypes().Return(fosite.Arguments{"token-exchange"})
				query, _ := url.ParseQuery("subject_token=ABCD.1234&subject_token_type=urn:ietf:params:oauth:token-type:access_token")
				areq.EXPECT().GetRequestForm().Return(query)

				coreChgen.EXPECT().AccessTokenSignature("ABCD.1234").Return("1234")
				coreStore.EXPECT().GetAccessTokenSession(nil, "1234", session).Return(delegatedAreq, nil)
				coreChgen.EXPECT().ValidateAccessToken(nil, delegatedAreq, "ABCD.1234").Return(nil)

				subjectTokenClient := &fosite.DefaultClient{}
				delegatedAreq.EXPECT().GetSubjectTokenClient().Times(2).Return(subjectTokenClient)
				storage.EXPECT().GetClient(nil, "").Return(subjectTokenClient, nil)
				areq.EXPECT().SetSubjectTokenClient(subjectTokenClient)

				session.GetExtraClaims()["act"] = `{"client_id":"service3","act":{"client_id":"service2","act":{"client_id":"gateway"}}}`
				delegatedAreq.EXPECT().GetSession().AnyTimes().Return(session)

				areq.EXPECT().GetRequestedScopes().Return([]string{"foo", "bar", "baz.bar"}).Times(1)
				areq.EXPECT().GetRequestedAudience().Return([]string{})
				areq.EXPECT().GetClient().Return(&fosite.DefaultClient{
					ID:         "exchange-client",
					GrantTypes: fosite.Arguments{"token-exchange"},
					Scopes:     []string{"foo", "bar", "baz"},
				})
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			err := h.HandleTokenEndpointRequest(nil, areq)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
				require.Equal(t, c.expectErr.(*fosite.RFC6749Error).HintField, errors.Unwrap(err).(*fosite.RFC6749Error).HintField)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTokenExchange_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockClientCredentialsGrantStorage(ctrl)
	chgen := internal.NewMockAccessTokenStrategy(ctrl)
	refresh := internal.NewMockRefreshTokenStrategy(ctrl)
	areq := fosite.NewAccessRequest(new(fosite.DefaultSession))
	aresp := fosite.NewAccessResponse()
	defer ctrl.Finish()

	h := Handler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStorage:  store,
			AccessTokenStrategy: chgen,
			AccessTokenLifespan: time.Hour,
		},
		RefreshTokenStrategy: refresh,
		RefreshTokenScopes:   []string{"offline", "offline_access"},
		ScopeStrategy:        fosite.HierarchicScopeStrategy,
	}
	for k, c := range []struct {
		description string
		mock        func()
		req         *http.Request
		expectErr   error
	}{
		{
			description: "should fail because not responsible",
			expectErr:   fosite.ErrUnknownRequest,
			mock: func() {
				areq.GrantTypes = fosite.Arguments{""}
			},
		},
		{
			description: "should fail because client not allowed",
			expectErr:   fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant: token-exchange."),
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"token-exchange"}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"foo"}}
			},
		},
		{
			description: "should pass",
			mock: func() {
				areq.GrantTypes = fosite.Arguments{"token-exchange"}
				areq.Session = &fosite.DefaultSession{}
				areq.Client = &fosite.DefaultClient{GrantTypes: fosite.Arguments{"token-exchange"}}
				chgen.EXPECT().GenerateAccessToken(nil, areq).Times(1).Return("tokenfoo.bar", "bar", nil)
				refresh.EXPECT().GenerateRefreshToken(nil, areq).Times(0)
				store.EXPECT().CreateAccessTokenSession(nil, "bar", gomock.Eq(areq.Sanitize([]string{}))).Times(1).Return(nil)
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.mock()
			err := h.PopulateTokenEndpointResponse(nil, areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
				require.Equal(t, c.expectErr.(*fosite.RFC6749Error).HintField, errors.Unwrap(err).(*fosite.RFC6749Error).HintField)
			} else {
				require.NoError(t, err)
				require.Equal(t, aresp.GetExtra("issued_token_type").(string), "urn:ietf:params:oauth:token-type:access_token")
			}
		})
	}
}
