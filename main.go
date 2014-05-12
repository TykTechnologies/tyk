package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/buger/goterm"
	"github.com/docopt/docopt.go"
	"html/template"
	"net/http"
	"net/http/httputil"
	"net/url"
)

/*
TODO: Configuration: set redis DB details
TODO: Redis storage manager
TODO: IP white list for admin functions
TODO: Flag to record analytics
*/

var log = logrus.New()
var authManager = AuthorisationManager{}
var sessionLimiter = SessionLimiter{}
var config = Config{}
var templates = &template.Template{}
var systemError string = "{\"status\": \"system error, please contact administrator\"}"

func displayConfig() {
	//	config_color := goterm.MAGENTA
	config_table := goterm.NewTable(0, 10, 5, ' ', 0)
	fmt.Fprintf(config_table, "Listening on port:\t%d\n", config.ListenPort)
	fmt.Fprintf(config_table, "Source path:\t%s\n", config.ListenPath)
	fmt.Fprintf(config_table, "Gateway target:\t%s\n", config.TargetUrl)

	fmt.Println(config_table)
	fmt.Println("")
}

func setupGlobals() {
	if config.Storage.Type == "memory" {
		log.Warning("Using in-memory storage. Warning: this is not scalable.")
		authManager = AuthorisationManager{
			&InMemoryStorageManager{
				map[string]string{}}}
	} else if config.Storage.Type == "redis" {
		log.Info("Using Redis storage manager.")
		authManager = AuthorisationManager{
			&RedisStorageManager{}}

		authManager.Store.Connect()
	}

	template_file := fmt.Sprintf("%s/error.json", config.TemplatePath)
	templates = template.Must(template.ParseFiles(template_file))
}

func init() {
	usage := `Tyk API Gateway.

	Usage:
		tyk [options]

	Options:
		-h --help      Show this screen
		--conf=FILE    Load a named configuration file

	`

	arguments, err := docopt.Parse(usage, nil, true, "Tyk v1.0", false)
	if err != nil {
		log.Println("Error while parsing arguments.")
		log.Fatal(err)
	}

	filename := "tyk.conf"
	value, _ := arguments["--conf"]
	if value != nil {
		log.Info(fmt.Sprintf("Using %s for configuration", value.(string)))
		filename = arguments["--conf"].(string)
	} else {
		log.Info("No configuration file defined, will try to use default (./tyk.conf)")
	}

	loadConfig(filename, &config)
	setupGlobals()

}

func intro() {
	fmt.Print("\n\n")
	fmt.Println(goterm.Bold(goterm.Color("Tyk.io Gateway API v0.1", goterm.GREEN)))
	fmt.Println(goterm.Bold(goterm.Color("=======================", goterm.GREEN)))
	fmt.Print("Copyright Jively Ltd. 2014")
	fmt.Print("\nhttp://www.tyk.io\n\n")
}

func main() {
	intro()
	displayConfig()

	remote, err := url.Parse(config.TargetUrl)
	if err != nil {
		log.Error("Culdn't parse target URL")
		log.Error(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)
	http.HandleFunc("/tyk/keys/create", securityHandler(createKeyHandler))
	http.HandleFunc("/tyk/keys/", securityHandler(keyHandler))
	http.HandleFunc(config.ListenPath, handler(proxy))
	targetPort := fmt.Sprintf(":%d", config.ListenPort)
	err = http.ListenAndServe(targetPort, nil)
	if err != nil {
		log.Error(err)
	}
}
