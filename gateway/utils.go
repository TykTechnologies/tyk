package gateway

import (
	"strconv"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/garyburd/redigo/redis"
)

var RedisPool = newPool()

func GetRedisConn() redis.Conn {
	c, err := redis.Dial("tcp",
		config.Global().RedisDBAppConfOptions.Host+":"+strconv.Itoa(config.Global().RedisDBAppConfOptions.Port),
		redis.DialDatabase(config.Global().RedisDBAppConfOptions.DB),
		redis.DialPassword(config.Global().RedisDBAppConfOptions.Password),
		redis.DialConnectTimeout(1*time.Second),
		redis.DialReadTimeout(1*time.Second),
		redis.DialWriteTimeout(1*time.Second))
	if err != nil {
		panic(err.Error())
	}

	return c
}

func newPool() *redis.Pool {
	return &redis.Pool{
		MaxIdle:   80,
		MaxActive: 12000, // max number of connections
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp",
				config.Global().RedisDBAppConfOptions.Host+":"+strconv.Itoa(config.Global().RedisDBAppConfOptions.Port),
				redis.DialDatabase(config.Global().RedisDBAppConfOptions.DB),
				redis.DialPassword(config.Global().RedisDBAppConfOptions.Password))
			if err != nil {
				panic(err.Error())
			}
			return c, err
		},
	}
}

func Append(slice, data []byte) []byte {
	l := len(slice)
	if l+len(data) > cap(slice) { // reallocate
		// Allocate double what's needed, for future growth.
		newSlice := make([]byte, (l+len(data))*2)
		// The copy function is predeclared and works for any slice type.
		copy(newSlice, slice)
		slice = newSlice
	}
	slice = slice[0 : l+len(data)]
	copy(slice[l:], data)
	return slice
}
