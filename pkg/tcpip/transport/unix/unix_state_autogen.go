// automatically generated by stateify.

package unix

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *connectionedEndpoint) beforeSave() {}
func (x *connectionedEndpoint) save(m state.Map) {
	x.beforeSave()
	var acceptedChan []*connectionedEndpoint = x.saveAcceptedChan()
	m.SaveValue("acceptedChan", acceptedChan)
	m.Save("baseEndpoint", &x.baseEndpoint)
	m.Save("id", &x.id)
	m.Save("idGenerator", &x.idGenerator)
	m.Save("stype", &x.stype)
}

func (x *connectionedEndpoint) afterLoad() {}
func (x *connectionedEndpoint) load(m state.Map) {
	m.Load("baseEndpoint", &x.baseEndpoint)
	m.Load("id", &x.id)
	m.Load("idGenerator", &x.idGenerator)
	m.Load("stype", &x.stype)
	m.LoadValue("acceptedChan", new([]*connectionedEndpoint), func(y interface{}) { x.loadAcceptedChan(y.([]*connectionedEndpoint)) })
}

func (x *connectionlessEndpoint) beforeSave() {}
func (x *connectionlessEndpoint) save(m state.Map) {
	x.beforeSave()
	m.Save("baseEndpoint", &x.baseEndpoint)
}

func (x *connectionlessEndpoint) afterLoad() {}
func (x *connectionlessEndpoint) load(m state.Map) {
	m.Load("baseEndpoint", &x.baseEndpoint)
}

func (x *ControlMessages) beforeSave() {}
func (x *ControlMessages) save(m state.Map) {
	x.beforeSave()
	m.Save("Rights", &x.Rights)
	m.Save("Credentials", &x.Credentials)
}

func (x *ControlMessages) afterLoad() {}
func (x *ControlMessages) load(m state.Map) {
	m.Load("Rights", &x.Rights)
	m.Load("Credentials", &x.Credentials)
}

func (x *message) beforeSave() {}
func (x *message) save(m state.Map) {
	x.beforeSave()
	m.Save("Entry", &x.Entry)
	m.Save("Data", &x.Data)
	m.Save("Control", &x.Control)
	m.Save("Address", &x.Address)
}

func (x *message) afterLoad() {}
func (x *message) load(m state.Map) {
	m.Load("Entry", &x.Entry)
	m.Load("Data", &x.Data)
	m.Load("Control", &x.Control)
	m.Load("Address", &x.Address)
}

func (x *queueReceiver) beforeSave() {}
func (x *queueReceiver) save(m state.Map) {
	x.beforeSave()
	m.Save("readQueue", &x.readQueue)
}

func (x *queueReceiver) afterLoad() {}
func (x *queueReceiver) load(m state.Map) {
	m.Load("readQueue", &x.readQueue)
}

func (x *streamQueueReceiver) beforeSave() {}
func (x *streamQueueReceiver) save(m state.Map) {
	x.beforeSave()
	m.Save("queueReceiver", &x.queueReceiver)
	m.Save("buffer", &x.buffer)
	m.Save("control", &x.control)
	m.Save("addr", &x.addr)
}

func (x *streamQueueReceiver) afterLoad() {}
func (x *streamQueueReceiver) load(m state.Map) {
	m.Load("queueReceiver", &x.queueReceiver)
	m.Load("buffer", &x.buffer)
	m.Load("control", &x.control)
	m.Load("addr", &x.addr)
}

func (x *connectedEndpoint) beforeSave() {}
func (x *connectedEndpoint) save(m state.Map) {
	x.beforeSave()
	m.Save("endpoint", &x.endpoint)
	m.Save("writeQueue", &x.writeQueue)
}

func (x *connectedEndpoint) afterLoad() {}
func (x *connectedEndpoint) load(m state.Map) {
	m.Load("endpoint", &x.endpoint)
	m.Load("writeQueue", &x.writeQueue)
}

func (x *baseEndpoint) beforeSave() {}
func (x *baseEndpoint) save(m state.Map) {
	x.beforeSave()
	m.Save("Queue", &x.Queue)
	m.Save("passcred", &x.passcred)
	m.Save("receiver", &x.receiver)
	m.Save("connected", &x.connected)
	m.Save("path", &x.path)
}

func (x *baseEndpoint) afterLoad() {}
func (x *baseEndpoint) load(m state.Map) {
	m.Load("Queue", &x.Queue)
	m.Load("passcred", &x.passcred)
	m.Load("receiver", &x.receiver)
	m.Load("connected", &x.connected)
	m.Load("path", &x.path)
}

func init() {
	state.Register("unix.connectionedEndpoint", (*connectionedEndpoint)(nil), state.Fns{Save: (*connectionedEndpoint).save, Load: (*connectionedEndpoint).load})
	state.Register("unix.connectionlessEndpoint", (*connectionlessEndpoint)(nil), state.Fns{Save: (*connectionlessEndpoint).save, Load: (*connectionlessEndpoint).load})
	state.Register("unix.ControlMessages", (*ControlMessages)(nil), state.Fns{Save: (*ControlMessages).save, Load: (*ControlMessages).load})
	state.Register("unix.message", (*message)(nil), state.Fns{Save: (*message).save, Load: (*message).load})
	state.Register("unix.queueReceiver", (*queueReceiver)(nil), state.Fns{Save: (*queueReceiver).save, Load: (*queueReceiver).load})
	state.Register("unix.streamQueueReceiver", (*streamQueueReceiver)(nil), state.Fns{Save: (*streamQueueReceiver).save, Load: (*streamQueueReceiver).load})
	state.Register("unix.connectedEndpoint", (*connectedEndpoint)(nil), state.Fns{Save: (*connectedEndpoint).save, Load: (*connectedEndpoint).load})
	state.Register("unix.baseEndpoint", (*baseEndpoint)(nil), state.Fns{Save: (*baseEndpoint).save, Load: (*baseEndpoint).load})
}
