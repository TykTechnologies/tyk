package main

type RoundRobin struct {
	pos, max, cur int
}

func (r *RoundRobin) SetMax(max int) {
	if r.max = max; r.max < 0 {
		r.max = 0
	}

	// Can't have a new list substituted that's shorter
	if r.cur > r.max {
		r.cur = 0
	}
	if r.pos > r.max {
		r.pos = 0
	}
}

func (r *RoundRobin) SetLen(len int) { r.SetMax(len - 1) }

func (r *RoundRobin) GetPos() int {
	r.cur = r.pos
	if r.pos++; r.pos > r.max {
		r.pos = 0
	}
	log.Debug("[ROUND ROBIN] Returning index: ", r.cur)
	return r.cur
}
