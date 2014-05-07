package main

import (
	"io/ioutil"
	"encoding/json"
)

type Config struct {
	ListenPath string `json:"listen_path"`
	ListenPort int `json:"listen_port"`
	TargetUrl string `json:"target_url"`
	Secret string `json:"secret"`
	TemplatePath string `json:"template_path"`
	Storage struct {
		Host string `json:"host"`
		Port int `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"storage"`
}

func LoadConfig(filePath string, configStruct *Config) {
	configuration, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Error("Couldn't load configuration file")
		log.Error(err)
	} else {
		err := json.Unmarshal(configuration, &configStruct)
		if err != nil {
			log.Error("Couldn't unmarshal configuration")
			log.Error(err)
		}
	}
}
