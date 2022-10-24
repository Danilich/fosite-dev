package rfc8693

import (
	"encoding/json"
	"github.com/iancoleman/orderedmap"
	"github.com/ory/fosite"
)

func createActHistory(subjectClientAct interface{}, client fosite.Client, request fosite.AccessRequester) {
	if subjectClientAct == nil {
		type ClientID struct {
			ID string `json:"client_id"`
		}
		clientJson, _ := json.Marshal(ClientID{ID: client.GetID()})
		request.GetSession().(fosite.ExtraClaimsSession).GetExtraClaims()["act"] = string(clientJson)
	} else {
		const act = "act"
		oldActMap := orderedmap.New()
		newActMap := orderedmap.New()

		actStr := subjectClientAct.(string)
		_ = json.Unmarshal([]byte(actStr), &oldActMap)
		newActMap.Set(`client_id`, client.GetID())
		newActMap.Set(act, oldActMap)
		actJson, _ := json.Marshal(newActMap)
		request.GetSession().(fosite.ExtraClaimsSession).GetExtraClaims()[act] = string(actJson)
	}
}
