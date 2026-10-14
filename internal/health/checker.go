package health

import "sync/atomic"

type Checker struct{ ready atomic.Bool }

func (c *Checker) SetReady(ready bool) { c.ready.Store(ready) }

func (c *Checker) IsReady() bool { return c != nil && c.ready.Load() }
