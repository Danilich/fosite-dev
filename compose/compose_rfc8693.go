package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/rfc8693"
)

//OAuth2TokenExchangeFactory creates a Token Exchange handler.
func OAuth2TokenExchangeFactory(config *Config, storage interface{}, strategy interface{}) interface{} {
	return &rfc8693.Handler{
		HandleHelper: &oauth2.HandleHelper{
			AccessTokenStorage:   storage.(oauth2.AccessTokenStorage),
			AccessTokenStrategy:  strategy.(oauth2.AccessTokenStrategy),
			AccessTokenLifespan:  config.GetAccessTokenLifespan(),
			RefreshTokenLifespan: config.GetRefreshTokenLifespan(),
		},
		ScopeStrategy:            config.GetScopeStrategy(),
		AudienceMatchingStrategy: config.GetAudienceStrategy(),
		RefreshTokenStrategy:     strategy.(oauth2.RefreshTokenStrategy),
		RefreshTokenScopes:       config.GetRefreshTokenScopes(),
		CoreStorage:              storage.(oauth2.CoreStorage),
		CoreStrategy:             strategy.(oauth2.CoreStrategy),
		Store:                    storage.(fosite.Storage),
	}
}
