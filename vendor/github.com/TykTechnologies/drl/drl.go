package drl

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type Server struct {
	HostName   string
	ID         string
	LoadPerSec int64
	Percentage float64
	TagHash    string
}

type DRL struct {
	Servers           *Cache
	mutex             sync.Mutex
	serverIndex       map[string]Server
	ThisServerID      string
	CurrentTotal      int64
	RequestTokenValue int
	currentTokenValue int64
	Ready             bool
}

func (d *DRL) SetCurrentTokenValue(newValue int64) {
	atomic.StoreInt64(&d.currentTokenValue, newValue)
}

func (d *DRL) CurrentTokenValue() int64 {
	return atomic.LoadInt64(&d.currentTokenValue)
}

func (d *DRL) Init() {
	d.Servers = NewCache(4 * time.Second)
	d.RequestTokenValue = 100
	d.mutex = sync.Mutex{}
	d.serverIndex = make(map[string]Server)
	d.Ready = true

	go func() {
		for {
			d.mutex.Lock()
			d.cleanServerList()
			d.mutex.Unlock()
			time.Sleep(5 * time.Second)
		}
	}()
}

func (d *DRL) uniqueID(s Server) string {
	uniqueID := s.ID + "|" + s.HostName
	return uniqueID
}

func (d *DRL) totalLoadAcrossServers() int64 {
	var total int64
	for sID, _ := range d.serverIndex {
		_, found := d.Servers.GetNoExtend(sID)
		if found {
			total += d.serverIndex[sID].LoadPerSec
		}
	}

	d.CurrentTotal = total

	return total
}

func (d *DRL) cleanServerList() {
	toRemove := map[string]bool{}
	for sID, _ := range d.serverIndex {
		_, found := d.Servers.GetNoExtend(sID)
		//fmt.Printf("Checking: %v found? %v\n", sID, found)
		if !found {
			toRemove[sID] = true
		}
	}

	// Update the server list
	for sID, _ := range toRemove {
		delete(d.serverIndex, sID)
	}
}

func (d *DRL) percentagesAcrossServers() {
	for sID, _ := range d.serverIndex {
		_, found := d.Servers.GetNoExtend(sID)
		if found {
			thisServerObject := d.serverIndex[sID]

			// The compensation should be flat out based on servers,
			// not on current load, it tends to skew too conservative
			thisServerObject.Percentage = 1 / float64(d.Servers.Count())
			d.serverIndex[sID] = thisServerObject
		}
	}
}

func (d *DRL) calculateTokenBucketValue() error {
	_, found := d.Servers.Get(d.ThisServerID)
	if !found {
		return errors.New("Apparently this server does not exist!")
	}
	// Use our own index
	thisServerObject := d.serverIndex[d.ThisServerID]

	var thisTokenValue float64
	thisTokenValue = float64(d.RequestTokenValue)

	if thisServerObject.Percentage > 0 {
		thisTokenValue = float64(d.RequestTokenValue) / thisServerObject.Percentage
	}

	rounded := Round(thisTokenValue, .5, 0)
	d.SetCurrentTokenValue(int64(rounded))
	return nil
}

func (d *DRL) AddOrUpdateServer(s Server) error {
	// Add or update the cache
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.uniqueID(s) != d.ThisServerID {
		thisServer, found := d.Servers.GetNoExtend(d.ThisServerID)
		if found {
			if thisServer.TagHash != s.TagHash {
				return errors.New("Node notification from different tag group, ignoring.")
			}
		} else {
			// We don't know enough about our own host, so let's skip for now until we do
			return errors.New("DRL has no information on current host, waiting...")
		}
	}

	if d.serverIndex != nil {
		d.serverIndex[d.uniqueID(s)] = s
	}
	d.Servers.Set(d.uniqueID(s), s)

	// Recalculate totals
	d.totalLoadAcrossServers()

	// Recalculate percentages
	d.percentagesAcrossServers()

	// Get the current token bucket value:
	calcErr := d.calculateTokenBucketValue()
	if calcErr != nil {
		return calcErr
	}

	return nil
}

func (d *DRL) Report() string {
	thisServer, found := d.Servers.GetNoExtend(d.ThisServerID)
	if found {
		return fmt.Sprintf("[Active Nodes]: %d [Token Bucket Value]: %d [Current Load p/s]: %d [Current Load]: %f", d.CurrentTotal, d.CurrentTokenValue, thisServer.LoadPerSec, thisServer.Percentage)
	}

	return "Error: server doesn't exist!"
}
