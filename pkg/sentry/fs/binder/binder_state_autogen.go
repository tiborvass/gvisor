// automatically generated by stateify.

package binder

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *Device) beforeSave() {}
func (x *Device) save(m state.Map) {
	x.beforeSave()
	m.Save("InodeSimpleAttributes", &x.InodeSimpleAttributes)
}

func (x *Device) afterLoad() {}
func (x *Device) load(m state.Map) {
	m.Load("InodeSimpleAttributes", &x.InodeSimpleAttributes)
}

func (x *Proc) beforeSave() {}
func (x *Proc) save(m state.Map) {
	x.beforeSave()
	m.Save("bd", &x.bd)
	m.Save("task", &x.task)
	m.Save("platform", &x.platform)
	m.Save("mapped", &x.mapped)
}

func (x *Proc) afterLoad() {}
func (x *Proc) load(m state.Map) {
	m.Load("bd", &x.bd)
	m.Load("task", &x.task)
	m.Load("platform", &x.platform)
	m.Load("mapped", &x.mapped)
}

func init() {
	state.Register("binder.Device", (*Device)(nil), state.Fns{Save: (*Device).save, Load: (*Device).load})
	state.Register("binder.Proc", (*Proc)(nil), state.Fns{Save: (*Proc).save, Load: (*Proc).load})
}
