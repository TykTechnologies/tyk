package kafka

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/IBM/sarama"
)

type KafkaOffsetResetRequest struct {
	Partition int32  `json:"partition"`
	Offset    int64  `json:"offset"`
	Timestamp *int64 `json:"timestamp"` // Unix timestamp in milliseconds
}

func NewKafkaOffsetResetHandler(client sarama.Client, consumerGroup, topic string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req KafkaOffsetResetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		var targetOffset int64 = req.Offset

		if req.Timestamp != nil {
			// Fetch offset by timestamp
			offsetReq := &sarama.OffsetRequest{Version: 1}
			offsetReq.AddBlock(topic, req.Partition, *req.Timestamp, 1)

			broker, err := client.Leader(topic, req.Partition)
			if err != nil {
				http.Error(w, "failed to find partition leader: "+err.Error(), http.StatusInternalServerError)
				return
			}

			resp, err := broker.GetAvailableOffsets(offsetReq)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			block := resp.GetBlock(topic, req.Partition)
			if block == nil || len(block.Offsets) == 0 {
				http.Error(w, "no offset found for timestamp", http.StatusNotFound)
				return
			}
			targetOffset = block.Offsets[0]
		}

		coordinator, err := client.Coordinator(consumerGroup)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		commitReq := &sarama.OffsetCommitRequest{
			ConsumerGroup:           consumerGroup,
			ConsumerGroupGeneration: sarama.GroupGenerationUndefined,
			Version:                 2,
		}
		commitReq.AddBlock(topic, req.Partition, targetOffset, time.Now().UnixMilli(), "")

		commitResp, err := coordinator.CommitOffset(commitReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := commitResp.Errors[topic][req.Partition]; err != sarama.ErrNoError {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "success",
			"offset": targetOffset,
		})
	}
}
