package rediscluster

import "strings"
import "strconv"
import "errors"
import "math/rand"
import "os"
import "sync"
import "github.com/TykTechnologies/logrus"
import iMap "github.com/TykTechnologies/concurrent-map"

const RedisClusterHashSlots = 16384
const RedisClusterRequestTTL = 16
const RedisClusterDefaultTimeout = 1

var log = logrus.New()

type RedisCluster struct {
	SeedHosts        ConcurrentMap      //map[string]bool
	Handles          ConcurrentMap      // map[string]*RedisHandle
	Slots            iMap.ConcurrentMap //map[uint16]string
	RefreshTableASAP bool
	singleRedisMode  bool
	poolConfig       PoolConfig
	Debug            bool

	muSingleRedisMode sync.RWMutex
}

type ClusterTransaction struct {
	Cmd  string
	Args []interface{}
}

func NewRedisCluster(seed_redii []map[string]string, poolConfig PoolConfig, debug bool) RedisCluster {
	cluster := RedisCluster{
		RefreshTableASAP:  false,
		singleRedisMode:   !poolConfig.IsCluster,
		SeedHosts:         NewCmap(),  //make(map[string]bool),
		Handles:           NewCmap(),  //make(map[string]*RedisHandle),
		Slots:             iMap.New(), // make(map[uint16]string),
		poolConfig:        poolConfig,
		Debug:             debug,
	}

	if cluster.Debug {
		log.Debug("[RedisCluster], PID", os.Getpid(), "StartingNewRedisCluster")
	}

	for _, redis := range seed_redii {
		for host, port := range redis {
			label := host + ":" + port
			cluster.SeedHosts.Set(label, true)
			cluster.Handles.Set(label, NewRedisHandle(host, port, poolConfig, debug))
		}
	}

	//for addr, _ := range cluster.SeedHosts {
	for item := range cluster.SeedHosts.Iter() {
		node := cluster.addRedisHandleIfNeeded(item.Key)
		cluster_enabled := cluster.hasClusterEnabled(node)
		if cluster_enabled == false {
			if cluster.SeedHosts.Count() == 1 {
				cluster.SetSingleRedisMode(true)
			} else {
				log.Fatal(errors.New("Multiple Seed Hosts Given, But Cluster Support Disabled in Redis"))
			}
		}
	}

	if cluster.SingleRedisMode() == false {
		cluster.populateSlotsCache()
	}
	return cluster
}

func (self *RedisCluster) hasClusterEnabled(node *RedisHandle) bool {
	_, err := node.Do("CLUSTER", "INFO")
	if err != nil {
		if err.Error() == "ERR This instance has cluster support disabled" ||
			err.Error() == "ERR unknown command 'CLUSTER'" {
			return false
		}
	}
	return true
}

// contact the startup nodes and try to fetch the hash slots -> instances
// map in order to initialize the Slots map.
func (self *RedisCluster) populateSlotsCache() {
	if self.SingleRedisMode() == true {
		return
	}
	if self.Debug {
		log.Info("[RedisCluster], PID", os.Getpid(), "[PopulateSlots Running]")
	}
	//for name, _ := range self.SeedHosts {
	for item := range self.SeedHosts.Iter() {
		if self.Debug {
			log.Info("[RedisCluster] [PopulateSlots] Checking: ", item.Key)
		}
		node := self.addRedisHandleIfNeeded(item.Key)
		cluster_info, err := node.Do("CLUSTER", "NODES")
		if err == nil {
			lines := strings.Split(string(cluster_info.([]uint8)), "\n")
			for _, line := range lines {
				if line != "" {
					fields := strings.Split(line, " ")
					addrField := fields[1]
					// Support Redis 4.x format that includes cluster bus port after "@"
					addrParts := strings.Split(addrField, "@")
					addr := addrParts[0]
					if addr == ":0" {
						addr = item.Key
					}
					// add to seedlist if not in cluster
					seedlist_exists := self.SeedHosts.Has(addr)
					if !seedlist_exists {
						self.SeedHosts.Set(addr, true)
					}
					// add to handles if not in handles
					self.addRedisHandleIfNeeded(item.Key)

					slots := fields[8:]
					for _, s_range := range slots {
						slot_range := s_range
						if slot_range != "[" {
							if self.Debug {
								log.Info("[RedisCluster] Considering Slot Range", slot_range)
							}
							r_pieces := strings.Split(slot_range, "-")
							min, _ := strconv.Atoi(r_pieces[0])
							max, _ := strconv.Atoi(r_pieces[1])
							for i := min; i <= max; i++ {
								self.Slots.Set(uint16(i), addr)
							}
						}
					}
				}
			}
			if self.Debug {
				log.Info("[RedisCluster] [Initializing] DONE, ",
					"Slots: ", self.Slots.Count(),
					"Handles So Far:", self.Handles.Count(),
					"SeedList:", self.SeedHosts.Count())
			}
			break
		}
	}
	self.switchToSingleModeIfNeeded()
}

func (self *RedisCluster) switchToSingleModeIfNeeded() {
	// catch case where we really intend to be on
	// single redis mode, but redis was not
	// started on time
	if self.SeedHosts.Count() == 1 &&
		self.Slots.Count() == 0 &&
		self.Handles.Count() == 1 {
		//for _, node := range self.Handles {
		for item := range self.Handles.Iter() {
			cluster_enabled := self.hasClusterEnabled(item.Val.(*RedisHandle))
			if cluster_enabled == false {
				self.SetSingleRedisMode(true)
			}
		}
	}
}

func (self *RedisCluster) addRedisHandleIfNeeded(addr string) *RedisHandle {
	handle_exists := self.Handles.Has(addr)
	if !handle_exists {
		pieces := strings.Split(addr, ":")
		self.Handles.Set(addr, NewRedisHandle(pieces[0], pieces[1], self.poolConfig, self.Debug))
	}

	item, _ := self.Handles.Get(addr)
	return item.(*RedisHandle)
}

//Goroutine safe setter for SingleRedisMode field
func (self *RedisCluster) SetSingleRedisMode(newValue bool) {
	self.muSingleRedisMode.Lock()
	self.singleRedisMode = newValue
	self.muSingleRedisMode.Unlock()
}

//Goroutine safe getter for SingleRedisMode field
func (self *RedisCluster) SingleRedisMode() bool {
	self.muSingleRedisMode.RLock()
	defer self.muSingleRedisMode.RUnlock()
	return self.singleRedisMode
}

func (self *RedisCluster) KeyForRequest(cmd string, args ...interface{}) string {
	cmd = strings.ToLower(cmd)
	if cmd == "info" ||
		cmd == "multi" ||
		cmd == "exec" ||
		cmd == "slaveof" ||
		cmd == "config" ||
		cmd == "shutdown" {
		return ""
	}
	if args[0] == nil {
		return ""
	}
	strs := args[0].([]interface{})
	if strs != nil && strs[0] != nil {
		switch strs[0].(type) {
		case string:
			return strs[0].(string)
		case int:
			asStr := strconv.Itoa(strs[0].(int))
			return asStr
		}
	}
	return ""
}

func (self *RedisCluster) KeyForTransaction(cmds []ClusterTransaction) string {
	for _, cmd := range cmds {
		key := self.KeyForRequest(cmd.Cmd, cmd.Args)
		if key != "" {
			log.Debug("Found key for transaction: ", key)
			return key
		}
	}
	return ""
}

// Return the hash slot from the key.
func (self *RedisCluster) SlotForKey(key string) uint16 {
	checksum := ChecksumCRC16([]byte(key))
	slot := checksum % RedisClusterHashSlots
	return slot
}

func (self *RedisCluster) RandomRedisHandle() *RedisHandle {
	if self.Handles.Count() == 0 {
		return nil
	}

	addrs := make([]string, 0)
	i := 0
	//for addr, _ := range self.Handles {
	for item := range self.Handles.Iter() {
		addrs = append(addrs, item.Key)
		i++
	}
	rand_addrs := make([]string, i)
	perm := rand.Perm(i)
	for j, v := range perm {
		rand_addrs[v] = addrs[j]
	}
	handle, _ := self.Handles.Get(rand_addrs[0])
	self.switchToSingleModeIfNeeded()
	return handle.(*RedisHandle)
}

// Given a slot return the link (Redis instance) to the mapped node.
// Make sure to create a connection with the node if we don't have
// one.
func (self *RedisCluster) RedisHandleForSlot(slot uint16) *RedisHandle {

	node, exists := self.Slots.Get(slot)
	// If we don't know what the mapping is, return a random node.
	if !exists {
		if self.Debug {
			log.Info("[RedisCluster] No One Appears Responsible For Slot: ", slot, "our slotsize is: ", self.Slots.Count())
		}
		return self.RandomRedisHandle()
	}

	cx_exists := self.Handles.Has(node.(string))
	// add to cluster if not in cluster
	if !cx_exists {
		pieces := strings.Split(node.(string), ":")
		self.Handles.Set(node.(string), NewRedisHandle(pieces[0], pieces[1], self.poolConfig, self.Debug))
		// XXX consider returning random if failure
	}

	handle, _ := self.Handles.Get(node.(string))
	return handle.(*RedisHandle)
}

func (self *RedisCluster) CloseConnection() {
	// If redis is down on start this may not exist
	if self != nil {
		self.disconnectAll()
	}
}

func (self *RedisCluster) disconnectAll() {
	if self.Debug {
		log.Info("[RedisCluster] PID:", os.Getpid(), " [Disconnect!] Had Handles:", self.Handles.Count())
	}
	// disconnect anyone in handles
	// for _, handle := range self.Handles {
	for item := range self.Handles.Iter() {
		item.Val.(*RedisHandle).Pool.Close()
	}
	// nuke handles
	//for addr, _ := range self.SeedHosts {
	for item := range self.SeedHosts.Iter() {
		// delete(self.Handles, item.Key)
		self.Handles.Remove(item.Key)
	}
	// nuke slots
	self.Slots = iMap.New()
}

func (self *RedisCluster) handleSingleMode(flush bool, cmd string, args ...interface{}) (reply interface{}, err error) {
	// for _, handle := range self.Handles {
	for item := range self.Handles.Iter() {
		if flush {
			return item.Val.(*RedisHandle).Do(cmd, args...)
		}
		return nil, item.Val.(*RedisHandle).Send(cmd, args...)
	}
	return nil, errors.New("no redis handle found for single mode")
}

func (self *RedisCluster) HandleTableRefresh() {
	if self.Debug {
		log.Info("[RedisCluster] Refresh Needed")
	}
	self.disconnectAll()
	self.populateSlotsCache()
	self.RefreshTableASAP = false
}

func (self *RedisCluster) SendClusterTransaction(cmds []ClusterTransaction) (reply interface{}, err error) {

	// forward onto first redis in the handle
	// if we are set to single mode
	if self.SingleRedisMode() == true {
		// for _, handle := range self.Handles {
		for item := range self.Handles.Iter() {
			log.Debug("Running transaction...")
			return item.Val.(*RedisHandle).DoTransaction(cmds)
		}
	}

	if self.RefreshTableASAP == true {
		self.HandleTableRefresh()
		if self.SingleRedisMode() == true {
			// for _, handle := range self.Handles {
			for item := range self.Handles.Iter() {
				return item.Val.(*RedisHandle).DoTransaction(cmds)
			}
		}
	}

	ttl := RedisClusterRequestTTL
	// Transactions are only for a ingle KEY for us here...
	key := self.KeyForTransaction(cmds)
	try_random_node := false
	asking := false
	for {
		if ttl <= 0 {
			break
		}
		ttl -= 1
		if key == "" {
			log.Error(errors.New("no way to dispatch this type of command to redis cluster"))
		}
		slot := self.SlotForKey(key)

		var redis *RedisHandle

		if self.Debug {
			log.Info("[RedisCluster] slot: ", slot, "key", key, "ttl", ttl)
		}

		if try_random_node {
			if self.Debug {
				log.Info("[RedisCluster] Trying Random Node")
			}
			redis = self.RandomRedisHandle()
			try_random_node = false
		} else {
			if self.Debug {
				log.Info("[RedisCluster] Trying Specific Node")
			}
			redis = self.RedisHandleForSlot(slot)
		}

		if redis == nil {
			if self.Debug {
				log.Info("[RedisCluster] could not get redis handle, bailing this round")
			}
			break
		}
		if self.Debug {
			log.Info("[RedisCluster] Got Host/Port: ", redis.Host, redis.Port)
		}

		if asking {
			if self.Debug {
				log.Info("ASKING")
			}
			redis.Send("ASKING")
			asking = false
		}

		var err error
		var resp interface{}

		resp, err = redis.DoTransaction(cmds)
		if err == nil {
			if self.Debug {
				log.Info("[RedisCluster] Success")
			}
			return resp, nil
		}

		// ok we are here so err is not nil
		errv := strings.Split(err.Error(), " ")
		if errv[0] == "MOVED" || errv[0] == "ASK" {
			if errv[0] == "ASK" {
				if self.Debug {
					log.Info("[RedisCluster] ASK")
				}
				asking = true
			} else {
				// Serve replied with MOVED. It's better for us to
				// ask for CLUSTER NODES the next time.
				SetRefreshNeeded()
				newslot, _ := strconv.Atoi(errv[1])
				newaddr := errv[2]
				self.Slots.Set(uint16(newslot), newaddr)
				if self.Debug {
					log.Info("[RedisCluster] MOVED newaddr: ", newaddr, "new slot: ", newslot, "my slots len: ", self.Slots.Count())
				}
			}
		} else {
			if self.Debug {
				log.Info("[RedisCluster] Other Error: ", err.Error())
			}
			try_random_node = true
		}
	}
	if self.Debug {
		log.Info("[RedisCluster] Failed Command")
	}
	return nil, errors.New("could not complete command")
}

func (self *RedisCluster) SendClusterPipeline(cmds []ClusterTransaction) (reply interface{}, err error) {

	// forward onto first redis in the handle
	// if we are set to single mode
	if self.SingleRedisMode() == true {
		// for _, handle := range self.Handles {
		for item := range self.Handles.Iter() {
			log.Debug("Running pipline...")
			return item.Val.(*RedisHandle).DoPipeline(cmds)
		}
	}

	if self.RefreshTableASAP == true {
		self.HandleTableRefresh()
		if self.SingleRedisMode() == true {
			// for _, handle := range self.Handles {
			for item := range self.Handles.Iter() {
				return item.Val.(*RedisHandle).DoPipeline(cmds)
			}
		}
	}

	ttl := RedisClusterRequestTTL
	// Transactions are only for a ingle KEY for us here...
	key := self.KeyForTransaction(cmds)
	try_random_node := false
	asking := false
	for {
		if ttl <= 0 {
			break
		}
		ttl -= 1
		if key == "" {
			log.Error(errors.New("no way to dispatch this type of command to redis cluster"))
		}
		slot := self.SlotForKey(key)

		var redis *RedisHandle

		if self.Debug {
			log.Info("[RedisCluster] slot: ", slot, "key", key, "ttl", ttl)
		}

		if try_random_node {
			if self.Debug {
				log.Info("[RedisCluster] Trying Random Node")
			}
			redis = self.RandomRedisHandle()
			try_random_node = false
		} else {
			if self.Debug {
				log.Info("[RedisCluster] Trying Specific Node")
			}
			redis = self.RedisHandleForSlot(slot)
		}

		if redis == nil {
			if self.Debug {
				log.Info("[RedisCluster] could not get redis handle, bailing this round")
			}
			break
		}
		if self.Debug {
			log.Info("[RedisCluster] Got Host/Port: ", redis.Host, redis.Port)
		}

		if asking {
			if self.Debug {
				log.Info("ASKING")
			}
			redis.Send("ASKING")
			asking = false
		}

		var err error
		var resp interface{}

		resp, err = redis.DoPipeline(cmds)
		if err == nil {
			if self.Debug {
				log.Info("[RedisCluster] Success")
			}
			return resp, nil
		}

		// ok we are here so err is not nil
		errv := strings.Split(err.Error(), " ")
		if errv[0] == "MOVED" || errv[0] == "ASK" {
			if errv[0] == "ASK" {
				if self.Debug {
					log.Info("[RedisCluster] ASK")
				}
				asking = true
			} else {
				// Serve replied with MOVED. It's better for us to
				// ask for CLUSTER NODES the next time.
				SetRefreshNeeded()
				newslot, _ := strconv.Atoi(errv[1])
				newaddr := errv[2]
				self.Slots.Set(uint16(newslot), newaddr)
				if self.Debug {
					log.Info("[RedisCluster] MOVED newaddr: ", newaddr, "new slot: ", newslot, "my slots len: ", self.Slots.Count())
				}
			}
		} else {
			if self.Debug {
				log.Info("[RedisCluster] Other Error: ", err.Error())
			}
			try_random_node = true
		}
	}
	if self.Debug {
		log.Info("[RedisCluster] Failed Command")
	}
	return nil, errors.New("could not complete command")
}

func (self *RedisCluster) SendClusterCommand(flush bool, cmd string, args ...interface{}) (reply interface{}, err error) {

	// forward onto first redis in the handle
	// if we are set to single mode
	if self.SingleRedisMode() == true {
		return self.handleSingleMode(flush, cmd, args...)
	}

	if self.RefreshTableASAP == true {
		self.HandleTableRefresh()
		// in case we realized we were now in Single Mode
		if self.SingleRedisMode() == true {
			return self.handleSingleMode(flush, cmd, args...)
		}
	}

	ttl := RedisClusterRequestTTL
	key := self.KeyForRequest(cmd, args)
	try_random_node := false
	asking := false
	for {
		if ttl <= 0 {
			break
		}
		ttl -= 1
		if key == "" {
			log.Error(errors.New("no way to dispatch this type of command to redis cluster"))
		}
		slot := self.SlotForKey(key)

		var redis *RedisHandle

		if self.Debug {
			log.Info("[RedisCluster] slot: ", slot, "key", key, "ttl", ttl)
		}

		if try_random_node {
			if self.Debug {
				log.Info("[RedisCluster] Trying Random Node")
			}
			redis = self.RandomRedisHandle()
			try_random_node = false
		} else {
			if self.Debug {
				log.Info("[RedisCluster] Trying Specific Node")
			}
			redis = self.RedisHandleForSlot(slot)
		}

		if redis == nil {
			if self.Debug {
				log.Info("[RedisCluster] could not get redis handle, bailing this round")
			}
			break
		}
		if self.Debug {
			log.Info("[RedisCluster] Got Host/Port: ", redis.Host, redis.Port)
		}

		if asking {
			if self.Debug {
				log.Info("ASKING")
			}
			redis.Send("ASKING")
			asking = false
		}

		var err error
		var resp interface{}

		if flush {
			resp, err = redis.Do(cmd, args...)
			if err == nil {
				if self.Debug {
					log.Info("[RedisCluster] Success")
				}
				return resp, nil
			}
		} else {
			err = redis.Send(cmd, args...)
			if err == nil {
				if self.Debug {
					log.Info("[RedisCluster] Success")
				}
				return nil, nil
			}
		}

		// ok we are here so err is not nil
		errv := strings.Split(err.Error(), " ")
		if errv[0] == "MOVED" || errv[0] == "ASK" {
			if errv[0] == "ASK" {
				if self.Debug {
					log.Info("[RedisCluster] ASK")
				}
				asking = true
			} else {
				// Serve replied with MOVED. It's better for us to
				// ask for CLUSTER NODES the next time.
				SetRefreshNeeded()
				newslot, _ := strconv.Atoi(errv[1])
				newaddr := errv[2]
				self.Slots.Set(uint16(newslot), newaddr)
				if self.Debug {
					log.Info("[RedisCluster] MOVED newaddr: ", newaddr, "new slot: ", newslot, "my slots len: ", self.Slots.Count())
				}
			}
		} else {
			if self.Debug {
				log.Info("[RedisCluster] Other Error: ", err.Error())
			}
			try_random_node = true
		}
	}
	if self.Debug {
		log.Info("[RedisCluster] Failed Command")
	}
	return nil, errors.New("could not complete command")
}

func (self *RedisCluster) Do(cmd string, args ...interface{}) (reply interface{}, err error) {
	return self.SendClusterCommand(true, cmd, args...)
}

func (self *RedisCluster) DoTransaction(cmds []ClusterTransaction) (reply interface{}, err error) {
	return self.SendClusterTransaction(cmds)
}

func (self *RedisCluster) DoPipeline(cmds []ClusterTransaction) (reply interface{}, err error) {
	return self.SendClusterPipeline(cmds)
}

func (self *RedisCluster) Send(cmd string, args ...interface{}) (err error) {
	_, err = self.SendClusterCommand(false, cmd, args...)
	return err
}

func (self *RedisCluster) SetRefreshNeeded() {
	self.RefreshTableASAP = true
}

func (self *RedisCluster) HandleForKey(key string) *RedisHandle {
	// forward onto first redis in the handle
	// if we are set to single mode
	if self.SingleRedisMode() == true {
		// for _, handle := range self.Handles {
		for item := range self.Handles.Iter() {
			return item.Val.(*RedisHandle)
		}
	}
	slot := self.SlotForKey(key)
	handle := self.RedisHandleForSlot(slot)
	return handle
}

type RedisClusterAccess interface {
	Do(commandName string, args ...interface{}) (reply interface{}, err error)
	Send(cmd string, args ...interface{}) (err error)
	SetRefreshNeeded()
	HandleForKey(key string) *RedisHandle
}

var Instance RedisCluster

func Do(commandName string, args ...interface{}) (reply interface{}, err error) {
	return Instance.Do(commandName, args...)
}

func Send(cmd string, args ...interface{}) (err error) {
	return Instance.Send(cmd, args...)
}

func SetRefreshNeeded() {
	Instance.SetRefreshNeeded()
}

func HandleForKey(key string) *RedisHandle {
	return Instance.HandleForKey(key)
}
