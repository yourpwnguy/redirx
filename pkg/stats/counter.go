package stats

import (
	"sync/atomic"
)

type Counters struct {
	Total uint64
	Mut   uint64
	Safe  uint64
	Bug   uint64
}

// atomic increments
func (c *Counters) IncMut()  { atomic.AddUint64(&c.Mut, 1) }
func (c *Counters) IncSafe() { atomic.AddUint64(&c.Safe, 1) }
func (c *Counters) IncBug()  { atomic.AddUint64(&c.Bug, 1) }

// atomic snapshot for UI
func (c *Counters) Snapshot() (mut, safe, bug, total uint64) {
	return atomic.LoadUint64(&c.Mut),
		atomic.LoadUint64(&c.Safe),
		atomic.LoadUint64(&c.Bug),
		c.Total
}
