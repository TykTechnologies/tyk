package kafka

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func parsePartitions(expr string) ([]int32, error) {
	if expr == "" {
		return nil, errors.New("empty partition expression")
	}

	rangeExpr := strings.Split(expr, "-")
	if len(rangeExpr) > 2 {
		return nil, fmt.Errorf("partition '%v' is invalid, only one range can be specified", expr)
	}

	if len(rangeExpr) == 1 {
		partition, err := strconv.ParseInt(expr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to parse partition number: %w", err)
		}
		return []int32{int32(partition)}, nil
	}

	start, err := strconv.ParseInt(rangeExpr[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse start of range: %w", err)
	}
	end, err := strconv.ParseInt(rangeExpr[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse end of range: %w", err)
	}

	var parts []int32
	for i := start; i <= end; i++ {
		parts = append(parts, int32(i))
	}
	return parts, nil
}

func parseTopics(sourceTopics []string, defaultOffset int64, allowExplicitOffsets bool) (topics []string, topicPartitions map[string]map[int32]int64, err error) {
	for _, t := range sourceTopics {
		// Split out comma-sep topics such as `foo,bar`
		for splitTopic := range strings.SplitSeq(t, ",") {
			// Trim whitespace so that `foo, bar` is still valid
			trimmed := strings.TrimSpace(splitTopic)
			if trimmed == "" {
				continue
			}

			// Split by colon, if any, allowing for `foo,1` or `foo:1:2` syntax
			// (topic, partition, offset)
			splitByColon := strings.Split(trimmed, ":")
			if len(splitByColon) == 1 {
				topics = append(topics, trimmed)
				continue
			}

			if len(splitByColon) > 3 {
				err = fmt.Errorf("topic '%v' is invalid, only one partition and an optional offset should be specified", trimmed)
				return
			}
			if len(splitByColon) == 3 && !allowExplicitOffsets {
				err = fmt.Errorf("topic '%v' is invalid, explicit offsets are not supported by this input", trimmed)
				return
			}

			// Extract topic, trimming whitespace again
			topic := strings.TrimSpace(splitByColon[0])

			// Extract a single partition or a range of the form 0-10
			var parts []int32
			if parts, err = parsePartitions(splitByColon[1]); err != nil {
				return
			}

			offset := defaultOffset
			if len(splitByColon) == 3 {
				if offset, err = strconv.ParseInt(splitByColon[2], 10, 64); err != nil {
					return
				}
			}

			if topicPartitions == nil {
				topicPartitions = map[string]map[int32]int64{}
			}

			partMap, exists := topicPartitions[topic]
			if !exists {
				partMap = map[int32]int64{}
				topicPartitions[topic] = partMap
			}

			for _, p := range parts {
				// If our specified offset is the default, then existing offsets
				// take precedence.
				if offset == defaultOffset {
					if _, exists := partMap[p]; exists {
						continue
					}
				}
				partMap[p] = offset
			}
		}
	}
	return
}
