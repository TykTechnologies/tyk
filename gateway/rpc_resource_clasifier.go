package gateway

import "strings"

type Classifier interface {
	classify([]string) map[string]interface{}
}

type DefaultRPCResourceClassifier struct {
}

func (d *DefaultRPCResourceClassifier) classify(keys []string) (
	keysToReset map[string]bool,
	TokensToBeRevoked,
	ClientsToBeRevoked,
	standardKeys,
	CertificatesToRemove,
	CertificatesToAdd,
	OauthClients map[string]string) {

	keysToReset = map[string]bool{}
	TokensToBeRevoked = map[string]string{}
	ClientsToBeRevoked = map[string]string{}
	standardKeys = map[string]string{}
	CertificatesToRemove = map[string]string{}
	CertificatesToAdd = map[string]string{}
	OauthClients = map[string]string{}

	for _, key := range keys {
		splitKeys := strings.Split(key, ":")
		if len(splitKeys) > 1 {
			action := splitKeys[len(splitKeys)-1]
			switch action {
			case ResetQuota:
				keysToReset[splitKeys[0]] = true
				standardKeys[key] = key
			case "hashed":
				standardKeys[key] = key
			case CertificateRemoved:
				CertificatesToRemove[key] = splitKeys[0]
			case CertificateAdded:
				CertificatesToAdd[key] = splitKeys[0]
			case OAuthRevokeToken, OAuthRevokeAccessToken, OAuthRevokeRefreshToken:
				TokensToBeRevoked[splitKeys[0]] = key
			case OAuthRevokeAllTokens:
				ClientsToBeRevoked[splitKeys[1]] = key
			case OauthClientAdded, OauthClientUpdated, OauthClientRemoved:
				OauthClients[splitKeys[0]] = action
			default:
				log.Debug("ignoring processing of action:", action)
			}
		} else {
			standardKeys[key] = key
		}
	}
	return
}
