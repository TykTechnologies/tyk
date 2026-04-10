package dnscache

type MockStorage struct {
	MockFetchItem func(key string) ([]string, error)
	MockGet       func(key string) (DnsCacheItem, bool)
	MockSet       func(key string, addrs []string)
	MockDelete    func(key string)
	MockClear     func()
}

func (ms *MockStorage) FetchItem(key string) ([]string, error) {
	return ms.MockFetchItem(key)
}

func (ms *MockStorage) Get(key string) (DnsCacheItem, bool) {
	return ms.MockGet(key)
}

func (ms *MockStorage) Set(key string, addrs []string) {
	ms.MockSet(key, addrs)
}

func (ms *MockStorage) Delete(key string) {
	ms.MockDelete(key)
}

func (ms *MockStorage) Clear() {
	ms.MockClear()
}
