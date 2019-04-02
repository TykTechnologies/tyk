package rediscluster

import "github.com/gomodule/redigo/redis"
import "os"
import "time"

type RedisHandle struct {
	Host string
	Port string
	Pool *redis.Pool
}

type PoolConfig struct {
	MaxIdle        int
	MaxActive      int
	IdleTimeout    time.Duration
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	Password       string
	Database       int
	IsCluster      bool
	UseTLS         bool
	TLSSkipVerify  bool
}

// XXX: add some password protection - DONE
func NewRedisHandle(host string, port string, poolConfig PoolConfig, debug bool) *RedisHandle {
	if debug {
		log.Info("[RedisHandle] Opening New Handle For Pid:", os.Getpid())
	}

	return &RedisHandle{
		Host: host,
		Port: port,
		Pool: &redis.Pool{
			MaxIdle:     poolConfig.MaxIdle,
			MaxActive:   poolConfig.MaxActive,
			IdleTimeout: poolConfig.IdleTimeout,
			Dial: func() (redis.Conn, error) {
				c, err := redis.Dial("tcp", host+":"+port, redis.DialUseTLS(poolConfig.UseTLS), redis.DialTLSSkipVerify(poolConfig.TLSSkipVerify), redis.DialPassword(poolConfig.Password), redis.DialDatabase(poolConfig.Database), redis.DialConnectTimeout(poolConfig.ConnectTimeout), redis.DialReadTimeout(poolConfig.ReadTimeout), redis.DialWriteTimeout(poolConfig.WriteTimeout))
				if err != nil {
					return nil, err
				}
				return c, nil
			},
		},
	}
}

func (self *RedisHandle) GetRedisConn() redis.Conn {
	log.Debug("Active TCP connections", self.Pool.ActiveCount())
	rc := self.Pool.Get()
	for i := 0; i < 6; i++ {
		err := rc.Err()
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			rc = self.Pool.Get()
		} else {
			break
		}
	}
	return rc
}

func (self *RedisHandle) Do(commandName string, args ...interface{}) (reply interface{}, err error) {
	rc := self.GetRedisConn()
	defer rc.Close()
	return rc.Do(commandName, args...)
}

// XXX: is _not_ calling defer rc.Close()
//      so do it yourself later
func (self *RedisHandle) Send(cmd string, args ...interface{}) (err error) {
	rc := self.GetRedisConn()
	return rc.Send(cmd, args...)
}

func (self *RedisHandle) DoTransaction(cmds []ClusterTransaction) (reply interface{}, err error) {
	rc := self.GetRedisConn()
	defer rc.Close()
	rc.Send("MULTI")
	for _, cmd := range cmds {
		sendErr := rc.Send(cmd.Cmd, cmd.Args...)
		if sendErr != nil {
			log.Error("Transacton failed: ", sendErr)
			break
		}
	}
	return rc.Do("EXEC")
}

func (self *RedisHandle) DoPipeline(cmds []ClusterTransaction) (reply interface{}, err error) {
	rc := self.GetRedisConn()
	defer rc.Close()
	var wasError bool
	var transErr error
	var rets []interface{} = make([]interface{}, len(cmds))
	for _, cmd := range cmds {
		sendErr := rc.Send(cmd.Cmd, cmd.Args...)
		if sendErr != nil {
			log.Error("Pipeline failed: ", sendErr)
			wasError = true
			transErr = err
			break
		}
	}
	rc.Flush()

	if !wasError {
		var newErr error
		for c := 0; c < (len(cmds) - 1); c++ {
			rets[c], newErr = rc.Receive()
			if newErr != nil {
				return rets, newErr
			}
		}
	}

	return rets, transErr
}
