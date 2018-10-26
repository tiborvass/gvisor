// automatically generated by stateify.

package host

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *descriptor) save(m state.Map) {
	x.beforeSave()
	m.Save("donated", &x.donated)
	m.Save("origFD", &x.origFD)
	m.Save("wouldBlock", &x.wouldBlock)
}

func (x *descriptor) load(m state.Map) {
	m.Load("donated", &x.donated)
	m.Load("origFD", &x.origFD)
	m.Load("wouldBlock", &x.wouldBlock)
	m.AfterLoad(x.afterLoad)
}

func (x *fileOperations) beforeSave() {}
func (x *fileOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("iops", &x.iops)
	m.Save("dirCursor", &x.dirCursor)
}

func (x *fileOperations) afterLoad() {}
func (x *fileOperations) load(m state.Map) {
	m.LoadWait("iops", &x.iops)
	m.Load("dirCursor", &x.dirCursor)
}

func (x *Filesystem) beforeSave() {}
func (x *Filesystem) save(m state.Map) {
	x.beforeSave()
	m.Save("paths", &x.paths)
}

func (x *Filesystem) afterLoad() {}
func (x *Filesystem) load(m state.Map) {
	m.Load("paths", &x.paths)
}

func (x *superOperations) beforeSave() {}
func (x *superOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("SimpleMountSourceOperations", &x.SimpleMountSourceOperations)
	m.Save("root", &x.root)
	m.Save("inodeMappings", &x.inodeMappings)
	m.Save("mounter", &x.mounter)
	m.Save("dontTranslateOwnership", &x.dontTranslateOwnership)
}

func (x *superOperations) afterLoad() {}
func (x *superOperations) load(m state.Map) {
	m.Load("SimpleMountSourceOperations", &x.SimpleMountSourceOperations)
	m.Load("root", &x.root)
	m.Load("inodeMappings", &x.inodeMappings)
	m.Load("mounter", &x.mounter)
	m.Load("dontTranslateOwnership", &x.dontTranslateOwnership)
}

func (x *inodeOperations) beforeSave() {}
func (x *inodeOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("fileState", &x.fileState)
	m.Save("cachingInodeOps", &x.cachingInodeOps)
}

func (x *inodeOperations) afterLoad() {}
func (x *inodeOperations) load(m state.Map) {
	m.LoadWait("fileState", &x.fileState)
	m.Load("cachingInodeOps", &x.cachingInodeOps)
}

func (x *inodeFileState) save(m state.Map) {
	x.beforeSave()
	if !state.IsZeroValue(x.queue) { m.Failf("queue is %v, expected zero", x.queue) }
	m.Save("mops", &x.mops)
	m.Save("descriptor", &x.descriptor)
	m.Save("sattr", &x.sattr)
	m.Save("savedUAttr", &x.savedUAttr)
}

func (x *inodeFileState) load(m state.Map) {
	m.LoadWait("mops", &x.mops)
	m.LoadWait("descriptor", &x.descriptor)
	m.LoadWait("sattr", &x.sattr)
	m.Load("savedUAttr", &x.savedUAttr)
	m.AfterLoad(x.afterLoad)
}

func (x *ConnectedEndpoint) save(m state.Map) {
	x.beforeSave()
	m.Save("queue", &x.queue)
	m.Save("path", &x.path)
	m.Save("ref", &x.ref)
	m.Save("readClosed", &x.readClosed)
	m.Save("writeClosed", &x.writeClosed)
	m.Save("srfd", &x.srfd)
	m.Save("stype", &x.stype)
}

func (x *ConnectedEndpoint) load(m state.Map) {
	m.Load("queue", &x.queue)
	m.Load("path", &x.path)
	m.Load("ref", &x.ref)
	m.Load("readClosed", &x.readClosed)
	m.Load("writeClosed", &x.writeClosed)
	m.LoadWait("srfd", &x.srfd)
	m.Load("stype", &x.stype)
	m.AfterLoad(x.afterLoad)
}

func (x *TTYFileOperations) beforeSave() {}
func (x *TTYFileOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("fileOperations", &x.fileOperations)
	m.Save("mu", &x.mu)
	m.Save("fgProcessGroup", &x.fgProcessGroup)
}

func (x *TTYFileOperations) afterLoad() {}
func (x *TTYFileOperations) load(m state.Map) {
	m.Load("fileOperations", &x.fileOperations)
	m.Load("mu", &x.mu)
	m.Load("fgProcessGroup", &x.fgProcessGroup)
}

func init() {
	state.Register("host.descriptor", (*descriptor)(nil), state.Fns{Save: (*descriptor).save, Load: (*descriptor).load})
	state.Register("host.fileOperations", (*fileOperations)(nil), state.Fns{Save: (*fileOperations).save, Load: (*fileOperations).load})
	state.Register("host.Filesystem", (*Filesystem)(nil), state.Fns{Save: (*Filesystem).save, Load: (*Filesystem).load})
	state.Register("host.superOperations", (*superOperations)(nil), state.Fns{Save: (*superOperations).save, Load: (*superOperations).load})
	state.Register("host.inodeOperations", (*inodeOperations)(nil), state.Fns{Save: (*inodeOperations).save, Load: (*inodeOperations).load})
	state.Register("host.inodeFileState", (*inodeFileState)(nil), state.Fns{Save: (*inodeFileState).save, Load: (*inodeFileState).load})
	state.Register("host.ConnectedEndpoint", (*ConnectedEndpoint)(nil), state.Fns{Save: (*ConnectedEndpoint).save, Load: (*ConnectedEndpoint).load})
	state.Register("host.TTYFileOperations", (*TTYFileOperations)(nil), state.Fns{Save: (*TTYFileOperations).save, Load: (*TTYFileOperations).load})
}