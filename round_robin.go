package main

type RoundRobin struct {
	pos int
	max int
	cur int
}

func (r *RoundRobin) SetMax(rp interface{}) {
	r.max = len(*rp.(*[]string))
}

func (r *RoundRobin) GetPos() int {
	r.cur = r.pos
	r.pos += 1
	if r.pos == (r.max) {
		r.pos = 0
	}
	log.Warning("Returning index: ", r.cur)
	return r.cur
}
