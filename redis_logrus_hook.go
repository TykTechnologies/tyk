package main

import (
	"time"

	"github.com/Sirupsen/logrus"
)

type redisChannelHook struct {
	Notifier  Notifier
	formatter logrus.Formatter
}

func NewRedisHook() *redisChannelHook {
	hook := &redisChannelHook{}
	hook.formatter = new(logrus.JSONFormatter)

	if config.PubSubMasterConnectionString == "" {
		// TODO: Deprecate this
		legacyNotifier := &RedisNotificationHandler{}
		legacyNotifier.Start()
		hook.Notifier = legacyNotifier
	} else {
		hook.Notifier = &TCFNotifier{channel: UIChanName}
	}

	return hook
}

func (hook *redisChannelHook) Fire(entry *logrus.Entry) error {

	orgId, found := entry.Data["org_id"]
	if !found {
		return nil
	}

	newEntry, err := hook.formatter.Format(entry)
	if err != nil {
		log.Error(err)
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
