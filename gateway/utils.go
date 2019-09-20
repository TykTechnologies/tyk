package gateway

import (
	"strconv"

	"github.com/TykTechnologies/tyk/config"
	"github.com/garyburd/redigo/redis"
)

var RedisPool = newPool()

func newPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle:   80,
		MaxActive: 12000, // max number of connections
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", config.Global().RedisDBAppConfOptions.Host+":"+strconv.Itoa(config.Global().RedisDBAppConfOptions.Port),
				redis.DialDatabase(config.Global().RedisDBAppConfOptions.DB), redis.DialPassword(config.Global().RedisDBAppConfOptions.Password))
			if err != nil {
				panic(err.Error())
			}
			return c, err
		},
	}
}
