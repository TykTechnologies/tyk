package apidef

// These are all known tyk event types. The string value is the code used to hook at
// the api definition JSON/BSON level. Register new event types here.
const (
	EventQuotaExceeded        TykEvent = "QuotaExceeded"
	EventRateLimitExceeded    TykEvent = "RatelimitExceeded"
	EventAuthFailure          TykEvent = "AuthFailure"
	EventKeyExpired           TykEvent = "KeyExpired"
	EventVersionFailure       TykEvent = "VersionFailure"
	EventOrgQuotaExceeded     TykEvent = "OrgQuotaExceeded"
	EventOrgRateLimitExceeded TykEvent = "OrgRateLimitExceeded"
	EventTriggerExceeded      TykEvent = "TriggerExceeded"
	EventBreakerTriggered     TykEvent = "BreakerTriggered"
	EventBreakerTripped       TykEvent = "BreakerTripped"
	EventBreakerReset         TykEvent = "BreakerReset"
	EventHOSTDOWN             TykEvent = "HostDown"
	EventHOSTUP               TykEvent = "HostUp"
	EventTokenCreated         TykEvent = "TokenCreated"
	EventTokenUpdated         TykEvent = "TokenUpdated"
	EventTokenDeleted         TykEvent = "TokenDeleted"
)
