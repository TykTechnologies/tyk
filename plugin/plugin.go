package plugin

import "net/http"

type Executor interface {
	Do(r *http.Request) error
}
