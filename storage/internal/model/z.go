package model

import (
	"fmt"
)

// Z represents an item in a ZSET
type Z struct {
	Member interface{}
	Score  float64
}

type ZS []Z

func (z ZS) Members() []string {
	if len(z) == 0 {
		return nil
	}
	result := make([]string, 0, len(z))
	for _, item := range z {
		result = append(result, fmt.Sprint(item.Member))
	}
	return result
}

func (z ZS) Scores() []float64 {
	if len(z) == 0 {
		return nil
	}
	result := make([]float64, 0, len(z))
	for _, item := range z {
		result = append(result, item.Score)
	}
	return result
}
