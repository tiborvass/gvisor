// automatically generated by stateify.

package route

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *commandKind) save(m state.Map) {
	m.SaveValue("", (int)(*x))
}

func (x *commandKind) load(m state.Map) {
	m.LoadValue("", new(int), func(y interface{}) { *x = (commandKind)(y.(int)) })
}

func (x *Protocol) beforeSave() {}
func (x *Protocol) save(m state.Map) {
	x.beforeSave()
}

func (x *Protocol) afterLoad() {}
func (x *Protocol) load(m state.Map) {
}

func init() {
	state.Register("route.commandKind", (*commandKind)(nil), state.Fns{Save: (*commandKind).save, Load: (*commandKind).load})
	state.Register("route.Protocol", (*Protocol)(nil), state.Fns{Save: (*Protocol).save, Load: (*Protocol).load})
}
