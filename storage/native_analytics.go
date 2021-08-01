package storage

import (
	"github.com/TykTechnologies/tyk/api"
)

var _ Analytics = (*nativeAnalytics)(nil)

type nativeAnalytics struct {
	client api.AnalyticsSync_SyncClient
}

func (n *nativeAnalytics) AppendToSetPipelined(key string, data [][]byte) {
	if n.client != nil {
		err := n.client.Send(&api.AnalyticsRecords{
			Key:  key,
			Data: data,
		})
		if err != nil {
			nativeLog.Error("Failed to send analytics data", err)
		}
	}
}

func (nativeAnalytics) GetAndDeleteSet(string) []interface{} { return nil }
func (nativeAnalytics) SetExp(string, int64) error           { return nil }
func (nativeAnalytics) GetExp(string) (int64, error)         { return 0, nil }
