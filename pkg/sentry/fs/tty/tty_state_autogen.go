// automatically generated by stateify.

package tty

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *dirInodeOperations) beforeSave() {}
func (x *dirInodeOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("msrc", &x.msrc)
	m.Save("attr", &x.attr)
	m.Save("master", &x.master)
	m.Save("slaves", &x.slaves)
	m.Save("dentryMap", &x.dentryMap)
	m.Save("next", &x.next)
}

func (x *dirInodeOperations) afterLoad() {}
func (x *dirInodeOperations) load(m state.Map) {
	m.Load("msrc", &x.msrc)
	m.Load("attr", &x.attr)
	m.Load("master", &x.master)
	m.Load("slaves", &x.slaves)
	m.Load("dentryMap", &x.dentryMap)
	m.Load("next", &x.next)
}

func (x *dirFileOperations) beforeSave() {}
func (x *dirFileOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("di", &x.di)
	m.Save("dirCursor", &x.dirCursor)
}

func (x *dirFileOperations) afterLoad() {}
func (x *dirFileOperations) load(m state.Map) {
	m.Load("di", &x.di)
	m.Load("dirCursor", &x.dirCursor)
}

func (x *filesystem) beforeSave() {}
func (x *filesystem) save(m state.Map) {
	x.beforeSave()
}

func (x *filesystem) afterLoad() {}
func (x *filesystem) load(m state.Map) {
}

func (x *superOperations) beforeSave() {}
func (x *superOperations) save(m state.Map) {
	x.beforeSave()
}

func (x *superOperations) afterLoad() {}
func (x *superOperations) load(m state.Map) {
}

func (x *inodeOperations) beforeSave() {}
func (x *inodeOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("uattr", &x.uattr)
}

func (x *inodeOperations) afterLoad() {}
func (x *inodeOperations) load(m state.Map) {
	m.Load("uattr", &x.uattr)
}

func (x *lineDiscipline) beforeSave() {}
func (x *lineDiscipline) save(m state.Map) {
	x.beforeSave()
	if !state.IsZeroValue(x.masterWaiter) { m.Failf("masterWaiter is %v, expected zero", x.masterWaiter) }
	if !state.IsZeroValue(x.slaveWaiter) { m.Failf("slaveWaiter is %v, expected zero", x.slaveWaiter) }
	m.Save("size", &x.size)
	m.Save("inQueue", &x.inQueue)
	m.Save("outQueue", &x.outQueue)
	m.Save("termios", &x.termios)
	m.Save("column", &x.column)
}

func (x *lineDiscipline) afterLoad() {}
func (x *lineDiscipline) load(m state.Map) {
	m.Load("size", &x.size)
	m.Load("inQueue", &x.inQueue)
	m.Load("outQueue", &x.outQueue)
	m.Load("termios", &x.termios)
	m.Load("column", &x.column)
}

func (x *outputQueueTransformer) beforeSave() {}
func (x *outputQueueTransformer) save(m state.Map) {
	x.beforeSave()
}

func (x *outputQueueTransformer) afterLoad() {}
func (x *outputQueueTransformer) load(m state.Map) {
}

func (x *inputQueueTransformer) beforeSave() {}
func (x *inputQueueTransformer) save(m state.Map) {
	x.beforeSave()
}

func (x *inputQueueTransformer) afterLoad() {}
func (x *inputQueueTransformer) load(m state.Map) {
}

func (x *masterInodeOperations) beforeSave() {}
func (x *masterInodeOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("inodeOperations", &x.inodeOperations)
	m.Save("d", &x.d)
}

func (x *masterInodeOperations) afterLoad() {}
func (x *masterInodeOperations) load(m state.Map) {
	m.Load("inodeOperations", &x.inodeOperations)
	m.Load("d", &x.d)
}

func (x *masterFileOperations) beforeSave() {}
func (x *masterFileOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("d", &x.d)
	m.Save("t", &x.t)
}

func (x *masterFileOperations) afterLoad() {}
func (x *masterFileOperations) load(m state.Map) {
	m.Load("d", &x.d)
	m.Load("t", &x.t)
}

func (x *queue) beforeSave() {}
func (x *queue) save(m state.Map) {
	x.beforeSave()
	var readBuf []byte = x.saveReadBuf()
	m.SaveValue("readBuf", readBuf)
	var waitBuf []byte = x.saveWaitBuf()
	m.SaveValue("waitBuf", waitBuf)
	m.Save("readable", &x.readable)
	m.Save("transformer", &x.transformer)
}

func (x *queue) afterLoad() {}
func (x *queue) load(m state.Map) {
	m.Load("readable", &x.readable)
	m.Load("transformer", &x.transformer)
	m.LoadValue("readBuf", new([]byte), func(y interface{}) { x.loadReadBuf(y.([]byte)) })
	m.LoadValue("waitBuf", new([]byte), func(y interface{}) { x.loadWaitBuf(y.([]byte)) })
}

func (x *slaveInodeOperations) beforeSave() {}
func (x *slaveInodeOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("inodeOperations", &x.inodeOperations)
	m.Save("d", &x.d)
	m.Save("t", &x.t)
}

func (x *slaveInodeOperations) afterLoad() {}
func (x *slaveInodeOperations) load(m state.Map) {
	m.Load("inodeOperations", &x.inodeOperations)
	m.Load("d", &x.d)
	m.Load("t", &x.t)
}

func (x *slaveFileOperations) beforeSave() {}
func (x *slaveFileOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("si", &x.si)
}

func (x *slaveFileOperations) afterLoad() {}
func (x *slaveFileOperations) load(m state.Map) {
	m.Load("si", &x.si)
}

func (x *Terminal) beforeSave() {}
func (x *Terminal) save(m state.Map) {
	x.beforeSave()
	m.Save("AtomicRefCount", &x.AtomicRefCount)
	m.Save("n", &x.n)
	m.Save("d", &x.d)
	m.Save("ld", &x.ld)
}

func (x *Terminal) afterLoad() {}
func (x *Terminal) load(m state.Map) {
	m.Load("AtomicRefCount", &x.AtomicRefCount)
	m.Load("n", &x.n)
	m.Load("d", &x.d)
	m.Load("ld", &x.ld)
}

func init() {
	state.Register("tty.dirInodeOperations", (*dirInodeOperations)(nil), state.Fns{Save: (*dirInodeOperations).save, Load: (*dirInodeOperations).load})
	state.Register("tty.dirFileOperations", (*dirFileOperations)(nil), state.Fns{Save: (*dirFileOperations).save, Load: (*dirFileOperations).load})
	state.Register("tty.filesystem", (*filesystem)(nil), state.Fns{Save: (*filesystem).save, Load: (*filesystem).load})
	state.Register("tty.superOperations", (*superOperations)(nil), state.Fns{Save: (*superOperations).save, Load: (*superOperations).load})
	state.Register("tty.inodeOperations", (*inodeOperations)(nil), state.Fns{Save: (*inodeOperations).save, Load: (*inodeOperations).load})
	state.Register("tty.lineDiscipline", (*lineDiscipline)(nil), state.Fns{Save: (*lineDiscipline).save, Load: (*lineDiscipline).load})
	state.Register("tty.outputQueueTransformer", (*outputQueueTransformer)(nil), state.Fns{Save: (*outputQueueTransformer).save, Load: (*outputQueueTransformer).load})
	state.Register("tty.inputQueueTransformer", (*inputQueueTransformer)(nil), state.Fns{Save: (*inputQueueTransformer).save, Load: (*inputQueueTransformer).load})
	state.Register("tty.masterInodeOperations", (*masterInodeOperations)(nil), state.Fns{Save: (*masterInodeOperations).save, Load: (*masterInodeOperations).load})
	state.Register("tty.masterFileOperations", (*masterFileOperations)(nil), state.Fns{Save: (*masterFileOperations).save, Load: (*masterFileOperations).load})
	state.Register("tty.queue", (*queue)(nil), state.Fns{Save: (*queue).save, Load: (*queue).load})
	state.Register("tty.slaveInodeOperations", (*slaveInodeOperations)(nil), state.Fns{Save: (*slaveInodeOperations).save, Load: (*slaveInodeOperations).load})
	state.Register("tty.slaveFileOperations", (*slaveFileOperations)(nil), state.Fns{Save: (*slaveFileOperations).save, Load: (*slaveFileOperations).load})
	state.Register("tty.Terminal", (*Terminal)(nil), state.Fns{Save: (*Terminal).save, Load: (*Terminal).load})
}
