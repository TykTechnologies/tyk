package gw_api

type APIStatusMessage struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func APIOk(msg string) APIStatusMessage {
	return APIStatusMessage{"ok", msg}
}

func APIError(msg string) APIStatusMessage {
	return APIStatusMessage{"error", msg}
}
