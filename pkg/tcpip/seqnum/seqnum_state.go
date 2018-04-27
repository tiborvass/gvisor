// automatically generated by stateify.

package seqnum

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *Value) save(m state.Map) {
	m.SaveValue("", (uint32)(*x))
}

func (x *Value) load(m state.Map) {
	m.LoadValue("", new(uint32), func(y interface{}) { *x = (Value)(y.(uint32)) })
}

func (x *Size) save(m state.Map) {
	m.SaveValue("", (uint32)(*x))
}

func (x *Size) load(m state.Map) {
	m.LoadValue("", new(uint32), func(y interface{}) { *x = (Size)(y.(uint32)) })
}

func init() {
	state.Register("seqnum.Value", (*Value)(nil), state.Fns{Save: (*Value).save, Load: (*Value).load})
	state.Register("seqnum.Size", (*Size)(nil), state.Fns{Save: (*Size).save, Load: (*Size).load})
}
