package gateway

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/v3/storage"
)

type redisChannelHook struct {
	notifier  RedisNotifier
	formatter logrus.Formatter
}

func newRedisHook() *redisChannelHook {
	hook := &redisChannelHook{}
	hook.formatter = new(logrus.JSONFormatter)
	hook.notifier.store = &storage.RedisCluster{KeyPrefix: "gateway-notifications:"}
	hook.notifier.channel = "dashboard.ui.messages"
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

	go hook.notifier.Notify(n)
	return nil
}

type InterfaceNotification struct {
	Type      string
	Message   string
	OrgID     string
	Timestamp time.Time
}

func (hook *redisChannelHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.InfoLevel,
		logrus.ErrorLevel,
		logrus.FatalLevel,
		logrus.PanicLevel,
	}
}
