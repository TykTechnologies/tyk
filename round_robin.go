package main

type RoundRobin struct {
	pos int
	max int
	cur int
}

func (r *RoundRobin) SetMax(rp []string) {
	r.max = len(rp)-1 //len(*rp.(*[]string)) - 1

	if r.max < 0 {
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

func (r *RoundRobin) GetPos() int {
	r.cur = r.pos
	r.pos += 1
	if r.pos > (r.max) {
		r.pos = 0
	}
	log.Debug("[ROUND ROBIN] Returning index: ", r.cur)
	return r.cur
}
