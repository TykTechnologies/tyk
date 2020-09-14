package redis

import "sync/atomic"

func (c *ClusterClient) DBSize() *IntCmd {
	cmd := NewIntCmd("dbsize")
	var size int64
	err := c.ForEachMain(func(main *Client) error {
		n, err := main.DBSize().Result()
		if err != nil {
			return err
		}
		atomic.AddInt64(&size, n)
		return nil
	})
	if err != nil {
		cmd.setErr(err)
		return cmd
	}
	cmd.val = size
	return cmd
}
