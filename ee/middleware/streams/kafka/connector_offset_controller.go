package kafka

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type resetClient interface {
	LeaveGroupContext(context.Context) error
	Close()
}

// ConnectorOffsetController serializes reset execution with the connector's
// poll loop, explicitly leaves the consumer group, and resumes polling only
// after the verified administrative reset has completed.
type ConnectorOffsetController struct {
	inner       OffsetController
	admin       OffsetResetAdmin
	group       string
	client      resetClient
	pollGate    *sync.RWMutex
	resetting   *atomic.Bool
	acks        *ExternalAckController
	pollPeriod  time.Duration
	coordinated bool
}

func (c *ConnectorOffsetController) EnableDistributedCoordination() { c.coordinated = true }

func NewConnectorOffsetController(inner OffsetController, admin OffsetResetAdmin, group string, client resetClient, pollGate *sync.RWMutex, resetting *atomic.Bool, acks *ExternalAckController) (*ConnectorOffsetController, error) {
	if inner == nil || admin == nil || group == "" || client == nil || pollGate == nil || resetting == nil {
		return nil, errors.New("complete connector reset dependencies are required")
	}
	return &ConnectorOffsetController{inner: inner, admin: admin, group: group, client: client, pollGate: pollGate, resetting: resetting, acks: acks, pollPeriod: 25 * time.Millisecond}, nil
}

func (c *ConnectorOffsetController) PlanReset(ctx context.Context, request ResetPlanRequest) (ResetPlan, error) {
	return c.inner.PlanReset(ctx, request)
}

func (c *ConnectorOffsetController) ExecuteReset(ctx context.Context, request ResetExecuteRequest) (ResetExecution, error) {
	if c.coordinated {
		return c.inner.ExecuteReset(ctx, request)
	}
	c.pollGate.Lock()
	defer c.pollGate.Unlock()
	if !c.resetting.CompareAndSwap(false, true) {
		return ResetExecution{}, controlError(http.StatusConflict, errors.New("reset already in progress"))
	}
	defer c.resetting.Store(false)
	if c.acks != nil {
		c.acks.InvalidateForReset()
	}
	if err := c.client.LeaveGroupContext(ctx); err != nil {
		return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
	}
	for {
		description, err := c.admin.DescribeGroup(ctx, c.group)
		if err != nil {
			return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
		}
		if len(description.Members) == 0 && (description.State == "Empty" || description.State == "empty") {
			break
		}
		select {
		case <-ctx.Done():
			return ResetExecution{}, controlError(http.StatusConflict, errors.New("consumer group did not quiesce"))
		case <-time.After(c.pollPeriod):
		}
	}
	execution, err := c.inner.ExecuteReset(ctx, request)
	if err != nil || execution.Status != "completed" {
		return execution, err
	}
	// Recreate the connector after altering broker state. A live franz-go client
	// retains an in-memory fetch position even after LeaveGroup; closing it is
	// the only unambiguous way to guarantee the next assignment starts from the
	// verified broker offset for every topic and partition.
	c.client.Close()
	return execution, nil
}
