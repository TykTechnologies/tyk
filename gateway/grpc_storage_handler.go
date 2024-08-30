package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"

	temporalmodel "github.com/TykTechnologies/storage/temporal/model"
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/dispatcher"
	"github.com/TykTechnologies/tyk/internal/cache"
	"github.com/TykTechnologies/tyk/internal/model"
	"github.com/TykTechnologies/tyk/rpc"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/sirupsen/logrus"
)

// GPCStorageHandler is a storage manager that uses gRPC to communicate with the server.
type GPCStorageHandler struct {
	KeyPrefix        string
	HashKeys         bool
	SuppressRegister bool
	DoReload         func()
	Gw               *Gateway `json:"-"`
	client           dispatcher.HandlerClient
	conn             *grpc.ClientConn
	cfg              *rpc.Config
}

// Custom JSON Codec
type jsonCodec struct{}

func (jsonCodec) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return "json"
}

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

func (r *GPCStorageHandler) Connect() bool {
	slaveOptions := r.Gw.GetConfig().SlaveOptions
	rpcConfig := rpc.Config{
		UseSSL:                slaveOptions.UseSSL,
		SSLInsecureSkipVerify: slaveOptions.SSLInsecureSkipVerify,
		SSLMinVersion:         r.Gw.GetConfig().HttpServerOptions.MinVersion,
		SSLMaxVersion:         r.Gw.GetConfig().HttpServerOptions.MaxVersion,
		ConnectionString:      slaveOptions.ConnectionString,
		RPCKey:                slaveOptions.RPCKey,
		APIKey:                slaveOptions.APIKey,
		GroupID:               slaveOptions.GroupID,
		CallTimeout:           slaveOptions.CallTimeout,
		PingTimeout:           slaveOptions.PingTimeout,
		RPCPoolSize:           slaveOptions.RPCPoolSize,
	}

	r.cfg = &rpcConfig

	var err error
	var opts = make([]grpc.DialOption, 0)
	if r.Gw.GetConfig().SlaveOptions.GRPCForceJSON {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})))
	}

	if r.Gw.GetConfig().SlaveOptions.UseSSL {

		clientCfg := &tls.Config{
			InsecureSkipVerify: rpcConfig.SSLInsecureSkipVerify,
			MinVersion:         rpcConfig.SSLMinVersion,
			MaxVersion:         rpcConfig.SSLMaxVersion,
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(clientCfg)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	addr := r.Gw.GetConfig().SlaveOptions.ConnectionString
	r.conn, err = grpc.Dial(addr, opts...) // Replace with actual server address
	if err != nil {
		log.Error("Failed to connect to gRPC server:", err)
		return false
	}
	r.client = dispatcher.NewHandlerClient(r.conn)
	rpc.SetConnected(true)

	time.Sleep(10 * time.Millisecond)

	return true
}

// Login handles the login process for a single client
func (r *GPCStorageHandler) Login(clientID, userKey string) bool {
	log := mainLog.WithFields(logrus.Fields{
		"func":     "Login",
		"clientID": clientID,
	})

	log.Debug("Attempting to login")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	request := &dispatcher.LoginRequest{
		ClientId: clientID,
		UserKey:  userKey,
	}

	response, err := r.client.Login(ctx, request)
	if err != nil {
		log.WithError(err).Error("Login failed")
		return false
	}

	if response == nil {
		log.Warning("Received nil response from Login")
		return false
	}

	if response.Success {
		log.Info("Login successful")
		r.setSessionData(clientID, userKey)
	} else {
		log.Warning("Login unsuccessful")
	}

	return response.Success
}

// LoginWithGroup handles the login process for a client within a group
func (r *GPCStorageHandler) LoginWithGroup(clientID string, groupData *apidef.GroupLoginRequest) bool {
	mainLog.WithFields(logrus.Fields{
		"func":     "LoginWithGroup",
		"clientID": clientID,
		"groupID":  groupData.GroupID,
	})

	log.Debug("Attempting to login with group")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nodeData := r.buildNodeInfo()

	request := &dispatcher.GroupLoginRequest{
		UserKey:   groupData.UserKey,
		GroupId:   groupData.GroupID,
		ForceSync: groupData.ForceSync,
		Node:      nodeData,
	}

	response, err := r.client.LoginWithGroup(ctx, request)
	if err != nil {
		log.WithError(err).Error("Group login failed")
		return false
	}

	if response == nil {
		log.Warning("Received nil response from LoginWithGroup")
		return false
	}

	if response.Success {
		log.Info("Group login successful")
		r.setGroupSessionData(clientID, groupData)
	} else {
		log.Warning("Group login unsuccessful")
	}

	return response.Success
}

// setSessionData stores session data after a successful login
func (r *GPCStorageHandler) setSessionData(clientID, userKey string) {
	// This is a placeholder. Implement according to your session management logic
	// For example, you might store this in a local cache or database
	log.WithField("clientID", clientID).Debug("Setting session data")
}

// setGroupSessionData stores session data after a successful group login
func (r *GPCStorageHandler) setGroupSessionData(clientID string, groupData *apidef.GroupLoginRequest) {
	// This is a placeholder. Implement according to your session management logic
	log.WithFields(logrus.Fields{
		"clientID": clientID,
		"groupID":  groupData.GroupID,
	}).Debug("Setting group session data")
}

func (r *GPCStorageHandler) buildNodeInfo() []byte {
	config := r.Gw.GetConfig()
	checkDuration := config.LivenessCheck.CheckDuration
	var intCheckDuration int64 = 10
	if checkDuration != 0 {
		intCheckDuration = int64(checkDuration / time.Second)
	}

	r.Gw.getHostDetails(r.Gw.GetConfig().PIDFileLocation)
	node := apidef.NodeData{
		NodeID:          r.Gw.GetNodeID(),
		GroupID:         config.SlaveOptions.GroupID,
		APIKey:          config.SlaveOptions.APIKey,
		NodeVersion:     VERSION,
		TTL:             intCheckDuration,
		NodeIsSegmented: config.DBAppConfOptions.NodeIsSegmented,
		Tags:            config.DBAppConfOptions.Tags,
		Health:          r.Gw.getHealthCheckInfo(),
		Stats: apidef.GWStats{
			APIsCount:     r.Gw.apisByIDLen(),
			PoliciesCount: r.Gw.PolicyCount(),
		},
		HostDetails: model.HostDetails{
			Hostname: r.Gw.hostDetails.Hostname,
			PID:      r.Gw.hostDetails.PID,
			Address:  r.Gw.hostDetails.Address,
		},
	}

	data, err := json.Marshal(node)
	if err != nil {
		log.Error("Error marshalling node info", err)
		return nil
	}

	return data
}

func (r *GPCStorageHandler) Disconnect() error {
	request := &dispatcher.GroupLoginRequest{
		UserKey: r.cfg.APIKey,
		GroupId: r.cfg.GroupID,
		Node:    r.buildNodeInfo(),
	}

	_, err := r.client.Disconnect(context.Background(), request)
	return err
}

func (r *GPCStorageHandler) getGroupLoginCallback(synchroniserEnabled bool) func(userKey string, groupID string) interface{} {
	groupLoginCallbackFn := func(userKey string, groupID string) interface{} {
		return &dispatcher.GroupLoginRequest{
			UserKey: userKey,
			GroupId: groupID,
			Node:    r.buildNodeInfo(),
		}
	}
	// TODO: Implement synchroniser logic if needed
	return groupLoginCallbackFn
}

func (r *GPCStorageHandler) hashKey(in string) string {
	if !r.HashKeys {
		return in
	}
	return storage.HashStr(in)
}

func (r *GPCStorageHandler) fixKey(keyName string) string {
	setKeyName := r.KeyPrefix + r.hashKey(keyName)
	log.Debug("Input key was: ", r.Gw.obfuscateKey(setKeyName))
	return setKeyName
}

func (r *GPCStorageHandler) cleanKey(keyName string) string {
	return strings.Replace(keyName, r.KeyPrefix, "", 1)
}

func (r *GPCStorageHandler) GetKey(keyName string) (string, error) {
	start := time.Now()
	value, err := r.GetRawKey(r.fixKey(keyName))
	elapsed := time.Since(start)
	log.Debug("GetKey took ", elapsed)
	return value, err
}

func (r *GPCStorageHandler) GetRawKey(keyName string) (string, error) {
	cacheEnabled := r.Gw.GetConfig().SlaveOptions.EnableRPCCache

	var cacheStore cache.Repository
	if cacheEnabled {
		cacheStore = r.Gw.RPCGlobalCache
		if strings.Contains(keyName, "cert-") {
			cacheStore = r.Gw.RPCCertCache
		}

		if cachedVal, found := cacheStore.Get(keyName); found {
			switch typedVal := cachedVal.(type) {
			case string:
				return typedVal, nil
			case error:
				return "", typedVal
			}
		}
	}

	request := &dispatcher.KeyRequest{
		ClientId: r.cfg.RPCKey,
		KeyName:  keyName,
	}

	response, err := r.client.GetKey(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
		if cacheEnabled {
			cacheStore.Set(keyName, storage.ErrKeyNotFound, 1)
		}
		return "", storage.ErrKeyNotFound
	}

	if cacheEnabled {
		cacheStore.Set(keyName, response.Value, cache.DefaultExpiration)
	}

	return response.Value, nil
}

func (r *GPCStorageHandler) GetMultiKey(keyNames []string) ([]string, error) {
	var err error
	var value string

	for _, key := range keyNames {
		value, err = r.GetKey(key)
		if err == nil {
			return []string{value}, nil
		}
	}

	return nil, err
}

func (r *GPCStorageHandler) GetExp(keyName string) (int64, error) {
	log.Debug("GetExp called")
	request := &dispatcher.KeyRequest{
		ClientId: r.cfg.RPCKey,
		KeyName:  r.fixKey(keyName),
	}

	response, err := r.client.GetExp(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
		log.Error("Error trying to get TTL: ", err)
		return 0, storage.ErrKeyNotFound
	}
	return response.Expiration, nil
}

func (r *GPCStorageHandler) SetExp(keyName string, timeout int64) error {
	log.Error("GPCStorageHandler.SetExp - Not Implemented")
	return nil
}

func (r *GPCStorageHandler) SetKey(keyName, session string, timeout int64) error {
	start := time.Now()
	request := &dispatcher.SetKeyRequest{
		ClientId: r.cfg.RPCKey,
		Data: &dispatcher.InboundData{
			KeyName:      r.fixKey(keyName),
			SessionState: session,
			Timeout:      timeout,
		},
	}

	_, err := r.client.SetKey(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
		log.Debug("Error trying to set value:", err)
		return err
	}

	elapsed := time.Since(start)
	log.Debug("SetKey took ", elapsed)
	return nil
}

func (r *GPCStorageHandler) SetRawKey(keyName, session string, timeout int64) error {
	return nil
}

func (r *GPCStorageHandler) Decrement(keyName string) {
	log.Warning("Decrement called")
	request := &dispatcher.KeyRequest{
		ClientId: r.cfg.RPCKey,
		KeyName:  keyName,
	}

	_, err := r.client.Decrement(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
	}
}

func (r *GPCStorageHandler) IncrememntWithExpire(keyName string, expire int64) int64 {
	request := &dispatcher.IncrementRequest{
		ClientId: r.cfg.RPCKey,
		Data: &dispatcher.InboundData{
			KeyName: keyName,
			Expire:  expire,
		},
	}

	response, err := r.client.IncrementWithExpire(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
		log.Warning("RPC increment returned error, returning 0")
		return 0
	}

	return response.Value
}

func (r *GPCStorageHandler) GetKeys(filter string) []string {
	log.Error("GPCStorageHandler.GetKeys - Not Implemented")
	return nil
}

func (r *GPCStorageHandler) GetKeysAndValuesWithFilter(filter string) map[string]string {
	searchStr := r.KeyPrefix + r.hashKey(filter) + "*"
	log.Debug("[STORE] Getting list by: ", searchStr)

	request := &dispatcher.SearchRequest{
		ClientId:     r.cfg.RPCKey,
		SearchString: searchStr,
	}

	response, err := r.client.GetKeysAndValuesWithFilter(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
		return nil
	}

	returnValues := make(map[string]string)
	for i, v := range response.Keys {
		returnValues[r.cleanKey(v)] = response.Values[i]
	}

	return returnValues
}

func (r *GPCStorageHandler) GetKeysAndValues() map[string]string {
	searchStr := r.KeyPrefix + "*"

	request := &dispatcher.SearchRequest{
		ClientId:     r.cfg.RPCKey,
		SearchString: searchStr,
	}

	response, err := r.client.GetKeysAndValues(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
		return nil
	}

	returnValues := make(map[string]string)
	for i, v := range response.Keys {
		returnValues[r.cleanKey(v)] = response.Values[i]
	}

	return returnValues
}

func (r *GPCStorageHandler) DeleteKey(keyName string) bool {
	log.Debug("DEL Key was: ", r.Gw.obfuscateKey(keyName))
	log.Debug("DEL Key became: ", r.Gw.obfuscateKey(r.fixKey(keyName)))
	request := &dispatcher.KeyRequest{
		ClientId: r.cfg.RPCKey,
		KeyName:  r.fixKey(keyName),
	}

	response, err := r.client.DeleteKey(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
		return false
	}

	return response.Success
}

func (r *GPCStorageHandler) DeleteAllKeys() bool {
	log.Warning("GPCStorageHandler.DeleteAllKeys - Not Implemented")
	return false
}

func (r *GPCStorageHandler) DeleteRawKey(keyName string) bool {
	request := &dispatcher.KeyRequest{
		ClientId: r.cfg.RPCKey,
		KeyName:  keyName,
	}

	response, err := r.client.DeleteRawKey(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
		return false
	}

	return response.Success
}

func (r *GPCStorageHandler) DeleteKeys(keys []string) bool {
	if len(keys) > 0 {
		asInterface := make([]string, len(keys))
		for i, v := range keys {
			asInterface[i] = r.fixKey(v)
		}

		log.Debug("Deleting: ", asInterface)
		request := &dispatcher.DeleteKeysRequest{
			ClientId: r.cfg.RPCKey,
			Keys:     asInterface,
		}

		response, err := r.client.DeleteKeys(context.Background(), request)
		if err != nil {
			if r.IsRetriableError(err) {
				// TODO: Implement retry logic
			}
			return false
		}

		return response.Success
	}
	log.Debug("GPCStorageHandler called DEL - Nothing to delete")
	return true
}

func (r *GPCStorageHandler) StartPubSubHandler(channel string, callback func(*temporalmodel.Message)) error {
	log.Warning("GPCStorageHandler.StartPubSubHandler - NO PUBSUB DEFINED")
	return nil
}

func (r *GPCStorageHandler) Publish(channel, message string) error {
	log.Warning("GPCStorageHandler.Publish - NO PUBSUB DEFINED")
	return nil
}

func (r *GPCStorageHandler) GetAndDeleteSet(keyName string) []interface{} {
	log.Error("GPCStorageHandler.GetAndDeleteSet - Not implemented, please disable your purger")
	return nil
}

func (r *GPCStorageHandler) AppendToSet(keyName, value string) {
	request := &dispatcher.AppendToSetRequest{
		ClientId: r.cfg.RPCKey,
		Data: &dispatcher.InboundData{
			KeyName: keyName,
			Value:   value,
		},
	}

	_, err := r.client.AppendToSet(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
	}
}

func (r *GPCStorageHandler) SetRollingWindow(keyName string, per int64, val string, pipeline bool) (int, []interface{}) {
	start := time.Now()
	request := &dispatcher.SetRollingWindowRequest{
		ClientId: r.cfg.RPCKey,
		Data: &dispatcher.InboundData{
			KeyName: keyName,
			Per:     per,
			Expire:  -1,
		},
	}

	response, err := r.client.SetRollingWindow(context.Background(), request)
	if err != nil {
		if r.IsRetriableError(err) {
			// TODO: Implement retry logic
		}
		log.Warning("RPC Handler: SetRollingWindow() returned error, returning 0")
		return 0, nil
	}

	elapsed := time.Since(start)
	log.Debug("SetRollingWindow took ", elapsed)

	return int(response.Count), nil
}

// GetApiDefinitions retrieves API definitions for a given organization ID and set of tags
func (r *GPCStorageHandler) GetApiDefinitions(orgId string, tags []string) string {
	log.WithFields(logrus.Fields{
		"orgId": orgId,
		"tags":  tags,
	}).Debug("Getting API definitions")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	request := &dispatcher.DefRequest{
		OrgId:   orgId,
		Tags:    tags,
		LoadOas: true,
	}

	response, err := r.client.GetApiDefinitions(ctx, request)
	if err != nil {
		log.WithError(err).Error("Failed to get API definitions")
		return ""
	}

	if response == nil {
		log.Warning("GetApiDefinitions response is nil")
		return ""
	}

	log.Debug("Successfully retrieved API definitions")
	return response.Definitions
}

// GetPolicies retrieves policies for a given organization ID
func (r *GPCStorageHandler) GetPolicies(orgId string) string {
	log.WithField("orgId", orgId).Debug("Getting policies")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	request := &dispatcher.OrgIdRequest{
		ClientId: r.cfg.RPCKey, // This field is empty in the original implementation
		OrgId:    orgId,
	}

	response, err := r.client.GetPolicies(ctx, request)
	if r.IsRetriableError(err) {
		fmt.Println("Retriable error in GetPolicies, will retry on next check", err)
		if r.Login(r.cfg.RPCKey, r.cfg.APIKey) {
			return r.GetPolicies(orgId)
		}
	}

	if response == nil {
		log.Warning("GetPolicies response is nil")
		return ""
	}

	log.Debug("Successfully retrieved policies")
	return response.Policies
}

// CheckForReload checks if a reload is required for the given organization
func (r *GPCStorageHandler) CheckForReload(orgId string) bool {
	log.Debug("Checking for reload")

	select {
	case <-r.Gw.ctx.Done():
		log.Debug("Context cancelled, aborting reload check")
		return false
	default:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	request := &dispatcher.OrgIdRequest{
		ClientId: r.cfg.RPCKey, // This field seems to be empty in the original implementation
		OrgId:    orgId,
	}

	response, err := r.client.CheckReload(ctx, request)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable, codes.DeadlineExceeded:
				log.WithError(err).Warning("Temporary error in CheckReload, will retry on next check")
			default:
				log.WithError(err).Error("Failed to check for reload")
			}
		} else {
			log.WithError(err).Error("Unknown error in CheckReload")
		}
		return true
	}

	if response == nil {
		log.Warning("Received nil response from CheckReload")
		return true
	}

	if response.ReloadRequired {
		log.Info("Reload required, triggering reload")
		go r.triggerReload()
	} else {
		log.Debug("No reload required")
	}

	return true
}

// triggerReload initiates the reload process
func (r *GPCStorageHandler) triggerReload() {
	log.Info("Triggering reload")

	// Use the existing notification system to trigger a reload
	r.Gw.MainNotifier.Notify(Notification{
		Command: NoticeGroupReload,
		Gw:      r.Gw,
	})

	// If you have a DoReload function set, call it
	if r.DoReload != nil {
		log.Debug("Calling DoReload function")
		r.DoReload()
	}
}

func (r *GPCStorageHandler) StartRPCKeepaliveWatcher() {
	//no-op
}
func (r *GPCStorageHandler) StartRPCLoopCheck(orgId string) {
	//no-op
}

func (r *GPCStorageHandler) GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{}) {
	// TODO: Implement
	return 0, nil
}

func (r *GPCStorageHandler) GetSet(keyName string) (map[string]string, error) {
	// TODO: Implement
	return nil, errors.New("GetSet not implemented")
}

func (r *GPCStorageHandler) AddToSet(keyName string, value string) {
	// TODO: Implement
}

func (r *GPCStorageHandler) RemoveFromSet(keyName string, value string) {
	// TODO: Implement
}

func (r *GPCStorageHandler) DeleteScanMatch(pattern string) bool {
	// TODO: Implement
	return false
}

func (r *GPCStorageHandler) GetKeyPrefix() string {
	// TODO: Implement
	return ""
}

func (r *GPCStorageHandler) AddToSortedSet(keyName string, value string, score float64) {
	// TODO: Implement
}

func (r *GPCStorageHandler) GetSortedSetRange(keyName, scoreFrom, scoreTo string) ([]string, []float64, error) {
	// TODO: Implement
	return nil, nil, errors.New("GetSortedSetRange not implemented")
}

func (r *GPCStorageHandler) RemoveSortedSetRange(keyName, scoreFrom, scoreTo string) error {
	// TODO: Implement
	return errors.New("RemoveSortedSetRange not implemented")
}

func (r *GPCStorageHandler) GetListRange(keyName string, from, to int64) ([]string, error) {
	// TODO: Implement
	return nil, errors.New("GetListRange not implemented")
}

func (r *GPCStorageHandler) RemoveFromList(keyName string, value string) error {
	// TODO: Implement
	return errors.New("RemoveFromList not implemented")
}

func (r *GPCStorageHandler) Exists(keyName string) (bool, error) {
	// TODO: Implement
	return false, errors.New("Exists not implemented")
}

const (
	maxRetries = 3
	baseDelay  = 100 * time.Millisecond
	maxDelay   = 2 * time.Second
)

// IsRetriableError checks if the error is retriable
func (r *GPCStorageHandler) IsRetriableError(err error) bool {
	if err == nil {
		return false
	}

	st, ok := status.FromError(err)
	if !ok {
		return false
	}

	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Aborted, codes.Internal:
		return true
	default:
		return false
	}
}

// retryOperation executes the operation with retries
func (r *GPCStorageHandler) retryOperation(operation func() error) error {
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err = operation()
		if err == nil {
			return nil
		}

		if !r.IsRetriableError(err) {
			return err
		}

		delay := r.calculateBackoff(attempt)
		select {
		case <-r.Gw.ctx.Done():
			return context.Canceled
		case <-time.After(delay):
			// Continue with retry
		}
	}
	return err
}

// calculateBackoff calculates the delay for exponential backoff
func (r *GPCStorageHandler) calculateBackoff(attempt int) time.Duration {
	delay := float64(baseDelay) * math.Pow(2, float64(attempt))
	return time.Duration(math.Min(float64(maxDelay), delay))
}
