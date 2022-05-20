package config_helper

type ConfigHelper struct {
	config interface{}
	prefix string

	envs []EnvVars
}

func New(config interface{}, prefix string) *ConfigHelper {
	cfg := ConfigHelper{config: config, prefix: prefix}
	cfg.Start()
	return &cfg
}

func (h *ConfigHelper) Start() {
	h.envs = parseEnvs(h.config)
}
