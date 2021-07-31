package storage

var _ Analytics = (*nativeAnalytics)(nil)

type nativeAnalytics struct{}

func (nativeAnalytics) AppendToSetPipelined(string, [][]byte) {}
func (nativeAnalytics) GetAndDeleteSet(string) []interface{}  { return nil }
func (nativeAnalytics) SetExp(string, int64) error            { return nil }
func (nativeAnalytics) GetExp(string) (int64, error)          { return 0, nil }
