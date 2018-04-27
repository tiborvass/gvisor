// automatically generated by stateify.

package unix

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *SocketOperations) beforeSave() {}
func (x *SocketOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("AtomicRefCount", &x.AtomicRefCount)
	m.Save("ReceiveTimeout", &x.ReceiveTimeout)
	m.Save("ep", &x.ep)
}

func (x *SocketOperations) afterLoad() {}
func (x *SocketOperations) load(m state.Map) {
	m.Load("AtomicRefCount", &x.AtomicRefCount)
	m.Load("ReceiveTimeout", &x.ReceiveTimeout)
	m.Load("ep", &x.ep)
}

func (x *provider) beforeSave() {}
func (x *provider) save(m state.Map) {
	x.beforeSave()
}

func (x *provider) afterLoad() {}
func (x *provider) load(m state.Map) {
}

func init() {
	state.Register("unix.SocketOperations", (*SocketOperations)(nil), state.Fns{Save: (*SocketOperations).save, Load: (*SocketOperations).load})
	state.Register("unix.provider", (*provider)(nil), state.Fns{Save: (*provider).save, Load: (*provider).load})
}
