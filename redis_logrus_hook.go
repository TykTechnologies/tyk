package main

import (
	"fmt"
	"github.com/TykTechnologies/logrus"
	"time"
)

type redisChannelHook struct {
	Notifier  RedisNotificationHandler
	formatter logrus.Formatter
}

func NewRedisHook() *redisChannelHook {
	hook := &redisChannelHook{}
	hook.formatter = new(logrus.JSONFormatter)
	hook.Notifier = RedisNotificationHandler{}
	hook.Notifier.Start()

	return hook
}

func (hook *redisChannelHook) Fire(entry *logrus.Entry) error {

	orgId, found := entry.Data["org_id"]
	if !found {
		return nil
	}

	newEntry, fmtErr := hook.formatter.Format(entry)
	if fmtErr != nil {
		fmt.Println(fmtErr)
		return nil
	}

	msg := string(newEntry)

	n := InterfaceNotification{
		Type:      "gateway-log",
		Message:   msg,
		OrgID:     orgId.(string),
		Timestamp: time.Now(),
	}

	go hook.Notifier.Notify(n)

	return nil
}

func (hook *redisChannelHook) Levels() []logrus.Level {

	return []logrus.Level{
		logrus.InfoLevel,
		logrus.ErrorLevel,
		logrus.FatalLevel,
		logrus.PanicLevel,
	}
}
