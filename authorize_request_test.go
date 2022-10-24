/*
 * Copyright © 2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author		Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @copyright 	2015-2018 Aeneas Rekkas <aeneas+oss@aeneas.io>
 * @license 	Apache-2.0
 *
 */

package fosite

import (
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizeRequestURLRegression(t *testing.T) {
	require.Nil(t, NewAuthorizeRequest().RedirectURI)
}

func TestAuthorizeRequest(t *testing.T) {
	var urlparse = func(rawurl string) *url.URL {
		u, _ := url.Parse(rawurl)
		return u
	}

	for k, c := range []struct {
		ar           *AuthorizeRequest
		isRedirValid bool
	}{
		{
			ar:           NewAuthorizeRequest(),
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				RedirectURI: urlparse("https://foobar"),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				RedirectURI: urlparse("https://foobar"),
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{""}},
				},
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{""}},
				},
				RedirectURI: urlparse(""),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{""}},
				},
				RedirectURI: urlparse(""),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				RedirectURI: urlparse("https://foobar.com#123"),
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{"https://foobar.com#123"}},
				},
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{RedirectURIs: []string{"https://foobar.com"}},
				},
				RedirectURI: urlparse("https://foobar.com#123"),
			},
			isRedirValid: false,
		},
		{
			ar: &AuthorizeRequest{
				Request: Request{
					Client:         &DefaultClient{RedirectURIs: []string{"https://foobar.com/cb"}},
					RequestedAt:    time.Now().UTC(),
					RequestedScope: []string{"foo", "bar"},
				},
				RedirectURI:   urlparse("https://foobar.com/cb"),
				ResponseTypes: []string{"foo", "bar"},
				State:         "foobar",
			},
			isRedirValid: true,
		},
	} {
		assert.Equal(t, c.ar.Client, c.ar.GetClient(), "%d", k)
		assert.Equal(t, c.ar.RedirectURI, c.ar.GetRedirectURI(), "%d", k)
		assert.Equal(t, c.ar.RequestedAt, c.ar.GetRequestedAt(), "%d", k)
		assert.Equal(t, c.ar.ResponseTypes, c.ar.GetResponseTypes(), "%d", k)
		assert.Equal(t, c.ar.RequestedScope, c.ar.GetRequestedScopes(), "%d", k)
		assert.Equal(t, c.ar.State, c.ar.GetState(), "%d", k)
		assert.Equal(t, c.isRedirValid, c.ar.IsRedirectURIValid(), "%d", k)

		c.ar.GrantScope("foo")
		c.ar.SetSession(&DefaultSession{})
		c.ar.SetRequestedScopes([]string{"foo"})
		assert.True(t, c.ar.GetGrantedScopes().Has("foo"))
		assert.True(t, c.ar.GetRequestedScopes().Has("foo"))
		assert.Equal(t, &DefaultSession{}, c.ar.GetSession())
	}
}
