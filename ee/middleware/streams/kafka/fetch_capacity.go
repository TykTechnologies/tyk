package kafka

import "sync"

type assignmentState struct {
	mu         sync.Mutex
	partitions map[string][]int32
}

func (s *assignmentState) add(assigned map[string][]int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.partitions == nil {
		s.partitions = make(map[string][]int32)
	}
	for topic, partitions := range assigned {
		for _, partition := range partitions {
			s.partitions[topic] = appendUniquePartition(s.partitions[topic], partition)
		}
	}
}

func (s *assignmentState) remove(revoked map[string][]int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for topic, partitions := range revoked {
		kept := s.partitions[topic][:0]
		for _, assigned := range s.partitions[topic] {
			if !containsPartition(partitions, assigned) {
				kept = append(kept, assigned)
			}
		}
		if len(kept) == 0 {
			delete(s.partitions, topic)
		} else {
			s.partitions[topic] = kept
		}
	}
}

func (s *assignmentState) snapshot() map[string][]int32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clonePartitionMap(s.partitions)
}

func partitionDifference(all, excluded map[string][]int32) map[string][]int32 {
	result := make(map[string][]int32)
	for topic, partitions := range all {
		for _, partition := range partitions {
			if !containsPartition(excluded[topic], partition) {
				result[topic] = append(result[topic], partition)
			}
		}
	}
	return result
}

func clonePartitionMap(source map[string][]int32) map[string][]int32 {
	result := make(map[string][]int32, len(source))
	for topic, partitions := range source {
		result[topic] = append([]int32(nil), partitions...)
	}
	return result
}

func appendUniquePartition(partitions []int32, partition int32) []int32 {
	if containsPartition(partitions, partition) {
		return partitions
	}
	return append(partitions, partition)
}

func containsPartition(partitions []int32, partition int32) bool {
	for _, candidate := range partitions {
		if candidate == partition {
			return true
		}
	}
	return false
}
