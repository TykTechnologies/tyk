package redis

import (
	"context"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"

	logger "github.com/TykTechnologies/tyk/log"
	"github.com/TykTechnologies/tyk/storage/internal/model"
)

type Driver struct {
	client UniversalClient
	log    *logrus.Logger
}

func NewDriver(client UniversalClient) *Driver {
	return &Driver{
		log:    logger.Get(),
		client: client,
	}
}

func (d *Driver) TTL(ctx context.Context, key string) (int64, error) {
	v, err := d.client.TTL(ctx, key).Result()
	return int64(v.Seconds()), err
}

func (d *Driver) Get(ctx context.Context, key string) (string, error) {
	return d.client.Get(ctx, key).Result()
}

func (d *Driver) Set(ctx context.Context, key, value string, duration time.Duration) error {
	return d.client.Set(ctx, key, value, duration).Err()
}

func (d *Driver) RPush(ctx context.Context, key, value string) error {
	return d.client.RPush(ctx, key, value).Err()
}

func (d *Driver) SAdd(ctx context.Context, key, value string) error {
	return d.client.SAdd(ctx, key, value).Err()
}

func (d *Driver) SRem(ctx context.Context, key, value string) error {
	return d.client.SRem(ctx, key, value).Err()
}

func (d *Driver) SIsMember(ctx context.Context, key, value string) (bool, error) {
	return d.client.SIsMember(ctx, key, value).Result()
}

func (d *Driver) SMembers(ctx context.Context, key string) ([]string, error) {
	return d.client.SMembers(ctx, key).Result()
}

func (d *Driver) Del(ctx context.Context, key string) error {
	return d.client.Del(ctx, key).Err()
}

func (d *Driver) FlushAll(ctx context.Context) (bool, error) {
	result, err := d.client.FlushAll(ctx).Result()
	return result == "OK", err
}

func (d *Driver) Incr(ctx context.Context, key string) (int64, error) {
	return d.client.Incr(ctx, key).Result()
}

func (d *Driver) Decr(ctx context.Context, key string) (int64, error) {
	return d.client.Decr(ctx, key).Result()
}

func (d *Driver) Exists(ctx context.Context, key string) (int64, error) {
	return d.client.Exists(ctx, key).Result()
}

func (d *Driver) ZAdd(ctx context.Context, key string, member string, score float64) (int64, error) {
	return d.client.ZAdd(ctx, key, NewZ(member, score)).Result()
}

func (d *Driver) Expire(ctx context.Context, key string, duration time.Duration) error {
	return d.client.Expire(ctx, key, duration).Err()
}

func scan(ctx context.Context, client *Client, pattern string) ([]string, error) {
	values := make([]string, 0)

	iter := client.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		values = append(values, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return values, nil
}

func (d *Driver) Keys(ctx context.Context, pattern string) ([]string, error) {
	var (
		err  error
		keys []string
	)

	switch v := d.client.(type) {
	case *ClusterClient:
		err = v.ForEachMaster(ctx, func(ctx context.Context, client *Client) error {
			values, err := scan(ctx, client, pattern)
			if err != nil {
				return err
			}
			keys = append(keys, values...)
			return nil
		})
	case *Client:
		keys, err = scan(ctx, v, pattern)
	}

	return keys, err
}

func (d *Driver) GetKeysAndValuesWithFilter(ctx context.Context, pattern string) (map[string]interface{}, error) {
	keys, err := d.Keys(ctx, pattern)
	if err != nil {
		return nil, err
	}

	return d.MGet(ctx, keys)
}

func (d *Driver) DeleteScanMatch(ctx context.Context, pattern string) (int64, error) {
	var (
		err  error
		keys []string
	)

	switch v := d.client.(type) {
	case *ClusterClient:
		err = v.ForEachMaster(ctx, func(ctx context.Context, client *Client) error {
			values, err := scan(ctx, client, pattern)
			if err != nil {
				return err
			}
			keys = append(keys, values...)
			return nil
		})
	case *Client:
		keys, err = scan(ctx, v, pattern)
	}

	if err != nil {
		return 0, err
	}
	return d.DeleteKeys(ctx, keys)
}

func (d *Driver) DeleteKeys(ctx context.Context, keys []string) (int64, error) {
	var (
		deleted int64
		errs    error
	)
	for _, name := range keys {
		err := d.client.Del(ctx, name).Err()
		if err != nil {
			errs = multierr.Append(errs, err)
			continue
		}
		deleted++
	}

	return deleted, errs
}

func (d *Driver) MGet(ctx context.Context, keys []string) (map[string]interface{}, error) {
	var err error
	values := []interface{}{}

	switch v := d.client.(type) {
	case *ClusterClient:
		getCmds := make([]*StringCmd, 0)
		pipe := v.Pipeline()
		for _, key := range keys {
			getCmds = append(getCmds, pipe.Get(ctx, key))
		}
		_, err := pipe.Exec(ctx)
		if err != nil && err != Nil {
			return nil, err
		}

		for _, val := range getCmds {
			values = append(values, val.Val())
		}
	case *Client:
		values, err = v.MGet(ctx, keys...).Result()
	}

	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{}
	for key, val := range values {
		result[keys[key]] = val
	}
	return result, nil

}

// SetRollingWindow will append to a sorted set in redis and extract a timed window of values
func (d *Driver) SetRollingWindow(ctx context.Context, keyName string, per int64, value_override string, pipeline bool) ([]string, error) {
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	client := d.client
	var zrange *StringSliceCmd

	pipeFn := func(pipe Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		zrange = pipe.ZRange(ctx, keyName, 0, -1)

		score := float64(now.UnixNano())
		member := value_override
		if member == "-1" {
			member = strconv.Itoa(int(now.UnixNano()))
		}

		pipe.ZAdd(ctx, keyName, NewZ(member, score))
		pipe.Expire(ctx, keyName, time.Duration(per)*time.Second)

		return nil
	}

	var err error
	if pipeline {
		_, err = client.Pipelined(ctx, pipeFn)
	} else {
		_, err = client.TxPipelined(ctx, pipeFn)
	}

	if err != nil {
		return nil, err
	}

	return zrange.Result()
}

// GetRollingWindow
func (d *Driver) GetRollingWindow(ctx context.Context, keyName string, per int64, pipeline bool) ([]string, error) {
	now := time.Now()
	onePeriodAgo := now.Add(time.Duration(-1*per) * time.Second)

	client := d.client
	var zrange *StringSliceCmd

	pipeFn := func(pipe Pipeliner) error {
		pipe.ZRemRangeByScore(ctx, keyName, "-inf", strconv.Itoa(int(onePeriodAgo.UnixNano())))
		zrange = pipe.ZRange(ctx, keyName, 0, -1)

		return nil
	}

	var err error
	if pipeline {
		_, err = client.Pipelined(ctx, pipeFn)
	} else {
		_, err = client.TxPipelined(ctx, pipeFn)
	}

	if err != nil {
		return nil, err
	}

	return zrange.Result()
}

// LRange
func (d *Driver) LRange(ctx context.Context, key string, start, stop int64) ([]string, error) {
	return d.client.LRange(ctx, key, start, stop).Result()
}

// LRem
func (d *Driver) LRem(ctx context.Context, key string, count int64, value interface{}) (int64, error) {
	return d.client.LRem(ctx, key, count, value).Result()
}

// ZRemRangeByScore
func (d *Driver) ZRemRangeByScore(ctx context.Context, key, min, max string) (int64, error) {
	return d.client.ZRemRangeByScore(ctx, key, min, max).Result()
}

// ZRemRangeByScore
func (d *Driver) ZRangeByScoreWithScores(ctx context.Context, key, min, max string) (model.ZS, error) {
	zRaw, err := d.client.ZRangeByScoreWithScores(ctx, key, &ZRangeBy{
		Min: min,
		Max: max,
	}).Result()
	if err != nil || len(zRaw) == 0 {
		return nil, err
	}

	return toZS(zRaw), nil
}

// Publish
func (d *Driver) Publish(ctx context.Context, channel, message string) (int64, error) {
	return d.client.Publish(ctx, channel, message).Result()
}
