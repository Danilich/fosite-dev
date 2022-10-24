package rfc8693

import (
	"context"
	"fmt"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
	"github.com/pkg/errors"
	"log"
	"time"
)

const errMsg = "The OAuth 2.0 Client is not allowed to request"

type Handler struct {
	*oauth2.HandleHelper
	ScopeStrategy            fosite.ScopeStrategy
	AudienceMatchingStrategy fosite.AudienceMatchingStrategy
	RefreshTokenStrategy     oauth2.RefreshTokenStrategy
	RefreshTokenScopes       []string
	oauth2.CoreStrategy
	oauth2.CoreStorage
	Store fosite.Storage
}

func (c *Handler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {

	if !c.CanHandleTokenEndpointRequest(request) {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	client := request.GetClient()

	// The client MUST authenticate with the authorization server
	if client.IsPublic() {
		return errors.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is marked as public and is thus not allowed to use authorization grant 'token-exchange'."))
	}

	if !client.GetGrantTypes().Has("token-exchange") {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'token-exchange'."))
	}

	form := request.GetRequestForm()

	// subject_token REQUIRED
	subjectToken := form.Get("subject_token")
	if subjectToken == "" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHintf("Required parameter subject_token is missing."))
	}

	// subject_token_type REQUIRED
	subjectTokenType := form.Get("subject_token_type")
	if subjectTokenType == "" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHint("Parameter 'subject_token_type' must be set"))
	} else if subjectTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		return errors.WithStack(fosite.ErrInvalidRequest.WithHint("Only subject_token_type=urn:ietf:params:oauth:token-type:access_token is supported"))
	}

	// resource OPTIONAL
	//TODO
	resource := form.Get("resource")
	if resource != "" {
		log.Println(resource)
	}

	signature := c.CoreStrategy.AccessTokenSignature(subjectToken)
	subjectReq, err := c.CoreStorage.GetAccessTokenSession(ctx, signature, request.GetSession())
	if err != nil {
		return errors.WithStack(fosite.ErrRequestUnauthorized.WithDebug(err.Error()))
	} else if err := c.CoreStrategy.ValidateAccessToken(ctx, subjectReq, subjectToken); err != nil {
		return err
	}

	var subTokenClientId string
	if subjectReq.GetSubjectTokenClient() == nil {
		subTokenClientId = subjectReq.GetClient().GetID()
	} else {
		subTokenClientId = subjectReq.GetSubjectTokenClient().GetID()
	}

	if client.GetID() == subTokenClientId {
		return errors.WithStack(fosite.ErrRequestForbidden.WithHint("Clients are not allowed to perform a token exchange on their own tokens"))
	}

	subjectTokenClient, err := c.Store.GetClient(ctx, subTokenClientId)
	if err != nil {
		return errors.WithStack(fosite.ErrInvalidClient.WithHint("The subject token OAuth2 Client does not exist."))
	}

	subjectClient, ok := subjectTokenClient.(fosite.TokenExchangeClient)
	if !ok {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to perform a token exchange for the given subject token."))
	}

	tokenExchangeReq, ok := request.(fosite.TokenExchangeAccessRequester)
	if !ok {
		return errors.WithStack(fosite.ErrInvalidRequestObject)
	}

	tokenExchangeReq.SetSubjectTokenClient(subjectClient)

	for _, scope := range request.GetRequestedScopes() {
		if !c.ScopeStrategy(client.GetScopes(), scope) {
			return errors.WithStack(fosite.ErrInvalidScope.WithHintf(fmt.Sprintf("%s scope %s.", errMsg, scope)))
		}
	}

	if err := c.AudienceMatchingStrategy(client.GetAudience(), request.GetRequestedAudience()); err != nil {
		return errors.WithStack(fosite.ErrInvalidTarget)
	}

	//https://tools.ietf.org/html/rfc8693#section-4.1
	//(Actor) Claim
	subjectClientAct := subjectReq.GetSession().(fosite.ExtraClaimsSession).GetExtraClaims()["act"]
	createActHistory(subjectClientAct, client, request)

	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(c.AccessTokenLifespan))
	if c.RefreshTokenLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(c.RefreshTokenLifespan).Round(time.Second))
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc8693#section-2.2
func (c *Handler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {

	if !c.CanHandleTokenEndpointRequest(request) {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("token-exchange") {
		return errors.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant: token-exchange."))
	}

	if request.GetGrantedScopes().HasOneOf(c.RefreshTokenScopes...) {
		refresh, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, request)
		if err != nil {
			return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
		}
		if refreshSignature != "" {
			if err := c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, request.Sanitize([]string{})); err != nil {
				if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage); rollBackTxnErr != nil {
					err = rollBackTxnErr
				}
				return errors.WithStack(fosite.ErrServerError.WithDebug(err.Error()))
			}
		}
		response.SetExtra("refresh_token", refresh)
	}

	response.SetIssuedTokenType("urn:ietf:params:oauth:token-type:access_token")

	return c.IssueAccessToken(ctx, request, response)
}
func (c *Handler) CanSkipClientAuth(requester fosite.AccessRequester) bool {
	return true
}

func (c *Handler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {

	// grant_type REQUIRED.
	// Value MUST be set to "token-exchange".
	return requester.GetGrantTypes().ExactOne("token-exchange")
}
