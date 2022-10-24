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

package fosite_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/fosite"
	. "github.com/ory/fosite/internal"
)

func TestWriteAccessError(t *testing.T) {
	f := &Fosite{}
	header := http.Header{}
	ctrl := gomock.NewController(t)
	rw := NewMockResponseWriter(ctrl)
	defer ctrl.Finish()

	rw.EXPECT().Header().AnyTimes().Return(header)
	rw.EXPECT().WriteHeader(http.StatusBadRequest)
	rw.EXPECT().Write(gomock.Any())

	f.WriteAccessError(rw, nil, ErrInvalidRequest)
}

func TestWriteAccessError_RFC6749(t *testing.T) {
	// https://tools.ietf.org/html/rfc6749#section-5.2

	f := &Fosite{}

	for k, c := range []struct {
		err                *RFC6749Error
		code               string
		debug              bool
		expectDebugMessage string
		includeExtraFields bool
	}{
		{ErrInvalidRequest.WithDebug("some-debug"), "invalid_request", true, "some-debug", true},
		{ErrInvalidRequest.WithDebugf("some-debug-%d", 1234), "invalid_request", true, "some-debug-1234", true},
		{ErrInvalidRequest.WithDebug("some-debug"), "invalid_request", false, "some-debug", true},
		{ErrInvalidClient.WithDebug("some-debug"), "invalid_client", false, "some-debug", true},
		{ErrInvalidGrant.WithDebug("some-debug"), "invalid_grant", false, "some-debug", true},
		{ErrInvalidScope.WithDebug("some-debug"), "invalid_scope", false, "some-debug", true},
		{ErrUnauthorizedClient.WithDebug("some-debug"), "unauthorized_client", false, "some-debug", true},
		{ErrUnsupportedGrantType.WithDebug("some-debug"), "unsupported_grant_type", false, "some-debug", true},
		{ErrUnsupportedGrantType.WithDebug("some-debug"), "unsupported_grant_type", false, "some-debug", false},
		{ErrUnsupportedGrantType.WithDebug("some-debug"), "unsupported_grant_type", true, "some-debug", false},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			f.SendDebugMessagesToClients = c.debug
			f.UseLegacyErrorFormat = c.includeExtraFields

			rw := httptest.NewRecorder()
			f.WriteAccessError(rw, nil, c.err)

			var params struct {
				Error       string `json:"error"`             // specified by RFC, required
				Description string `json:"error_description"` // specified by RFC, optional
				Debug       string `json:"error_debug"`
				Hint        string `json:"error_hint"`
			}

			require.NotNil(t, rw.Body)
			err := json.NewDecoder(rw.Body).Decode(&params)
			require.NoError(t, err)

			assert.Equal(t, c.code, params.Error)
			if !c.includeExtraFields {
				assert.Empty(t, params.Debug)
				assert.Empty(t, params.Hint)
				assert.Contains(t, params.Description, c.err.DescriptionField)
				assert.Contains(t, params.Description, c.err.HintField)

				if c.debug {
					assert.Contains(t, params.Description, c.err.DebugField)
				} else {
					assert.NotContains(t, params.Description, c.err.DebugField)
				}
			} else {
				assert.EqualValues(t, c.err.DescriptionField, params.Description)
				assert.EqualValues(t, c.err.HintField, params.Hint)

				if !c.debug {
					assert.Empty(t, params.Debug)
				} else {
					assert.EqualValues(t, c.err.DebugField, params.Debug)
				}
			}
		})
	}
}
