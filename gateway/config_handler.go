package gateway

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/headers"
	"github.com/TykTechnologies/tyk/storage"
)




func (gw *Gateway) configsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		doJSONWrite(w, http.StatusMethodNotAllowed, apiError(http.StatusText(http.StatusMethodNotAllowed)))
		return
	}

	cfgs, err := gw.configStorage.GetConfigs()
	if err != nil {
		doJSONWrite(w, http.StatusInternalServerError,apiError(http.StatusText(http.StatusInternalServerError)))
		return
	}

	w.Header().Set("Content-Type", headers.ApplicationJSON)
	doJSONWrite(w, http.StatusOK, cfgs)

}


const DEFAULT_CONFIG_INDEX = "tyk_config_index"

type ConfigHandler interface {
	Init(store storage.Handler)
	Store(nodeID string,config config.Config) error
	GetConfigs() (map[string]interface{},error)
	DeleteConfigs(nodeID string) error
}

type DefaultConfigHandler struct{
	store storage.Handler
}


func (c *DefaultConfigHandler) Init(store storage.Handler) {
	c.store = store
	c.store.Connect()
}

/*

"tyk_config_index"[
	tyk_gw_ID
	tyk_pmp_ID
	tyk_pmp_ID2

	NY_tyk_gw_2
	NY_tyk_gw_1
	NY_tyk_pmp_1
	NY_tyk_pmp_2
]

edge logoff -> check if it's the last from its group, remove all from that group
if not, just remove the gw cfg

if the pump die -> it's going to delete itself

----

	NY_tyk_gw_2
	NY_tyk_gw_1
	NY_tyk_pmp_1
	NY_tyk_pmp_2

1- NY_tyk_gw_1 disconnect
2 - delete redis gw_1 cfg
3- send to MDCB a logoff signal + new group configs
4- MDCB to check if it's the last NY gw, since it's not, just update
5- NY_tyk_gw_2 disconnect
6- delete redis gw_2 cfg
7- SINCE it's the last gw from NY, delete every config from NY group (including pumps)
8- gw_3 from NY connect
9- get redis info (there'll be boths connected)
10- sends cfgs to MDCB
11- everything visible in MDCB now :D
.

.

tyk_gw_ID_config: "{}"
tyk_pump_ID_config:"{}"
tyk_pump_ID2_config:"{}"
*/

func (c *DefaultConfigHandler) Store(nodeID string,config config.Config) error{
	if c.store != nil {
		gwName := "tyk_gw_config"+"_"+nodeID

		c.store.AppendToSet(DEFAULT_CONFIG_INDEX,gwName)

		cfgBytes, _ := json.Marshal(config)
		err := c.store.SetKey(gwName,string(cfgBytes),-1)
		if err != nil {
			log.Error("error storing config ", err)
			return errors.New("error config store")
		}
		return nil
	}
	return errors.New("no store configured")
}

func (c *DefaultConfigHandler) GetConfigs() (map[string]interface{},error) {
	res := make(map[string]interface{})

	indexes, err := c.store.GetListRange(DEFAULT_CONFIG_INDEX, 0, -1)
	if err != nil {
		log.Error("error getting config index list:",err)
		return res,err
	}

	for _, key := range indexes {
		val, errKey := c.store.GetKey(key)
		if errKey != nil {
			log.Error("error getting key:",errKey)
			continue
		}
		aux:= make(map[string]interface{})
		json.Unmarshal([]byte(val),&aux)
		res[key] = aux
	}

	return res,nil
}

func (c *DefaultConfigHandler) DeleteConfigs(nodeID string) error{
	if c.store != nil {
		gwName := "tyk_gw_config"+"_"+nodeID
		c.store.RemoveFromList(DEFAULT_CONFIG_INDEX, gwName)
		ok := c.store.DeleteKey(gwName)
		if !ok {
			log.Error("error deleting gw config from Redis")
		}
	}
	return nil
}
