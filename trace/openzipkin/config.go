package openzipkin

import "encoding/json"

type Config struct {
	Reporter Reporter `json:"reporter"`
	Sampler  Sampler  `json:"sampler"`
}

type Reporter struct {
	URL        string `json:"url"`
	BatchSize  int    `json:"batch_size"`
	MaxBacklog int    `json:"max_backlog"`
}

type Sampler struct {
	Name string  `json:"name"`
	Rate float64 `json:"rate"`
	Salt int64   `json:"salt"`
	Mod  uint64  `json:"mod"`
}

func Load(opts map[string]interface{}) (*Config, error) {
	b, err := json.Marshal(opts)
	if err != nil {
		return nil, err
	}
	var c Config
	err = json.Unmarshal(b, &c)
	return &c, nil
}
