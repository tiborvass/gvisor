// automatically generated by stateify.

package loader

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *byteReader) beforeSave() {}
func (x *byteReader) save(m state.Map) {
	x.beforeSave()
	m.Save("NoopRelease", &x.NoopRelease)
	m.Save("PipeSeek", &x.PipeSeek)
	m.Save("NotDirReaddir", &x.NotDirReaddir)
	m.Save("NoFsync", &x.NoFsync)
	m.Save("NoopFlush", &x.NoopFlush)
	m.Save("NoMMap", &x.NoMMap)
	m.Save("NoIoctl", &x.NoIoctl)
	m.Save("AlwaysReady", &x.AlwaysReady)
	m.Save("data", &x.data)
}

func (x *byteReader) afterLoad() {}
func (x *byteReader) load(m state.Map) {
	m.Load("NoopRelease", &x.NoopRelease)
	m.Load("PipeSeek", &x.PipeSeek)
	m.Load("NotDirReaddir", &x.NotDirReaddir)
	m.Load("NoFsync", &x.NoFsync)
	m.Load("NoopFlush", &x.NoopFlush)
	m.Load("NoMMap", &x.NoMMap)
	m.Load("NoIoctl", &x.NoIoctl)
	m.Load("AlwaysReady", &x.AlwaysReady)
	m.Load("data", &x.data)
}

func (x *fileContext) beforeSave() {}
func (x *fileContext) save(m state.Map) {
	x.beforeSave()
	m.Save("Context", &x.Context)
}

func (x *fileContext) afterLoad() {}
func (x *fileContext) load(m state.Map) {
	m.Load("Context", &x.Context)
}

func (x *VDSO) beforeSave() {}
func (x *VDSO) save(m state.Map) {
	x.beforeSave()
	var phdrs []elfProgHeader = x.savePhdrs()
	m.SaveValue("phdrs", phdrs)
	m.Save("ParamPage", &x.ParamPage)
	m.Save("vdso", &x.vdso)
	m.Save("os", &x.os)
	m.Save("arch", &x.arch)
}

func (x *VDSO) afterLoad() {}
func (x *VDSO) load(m state.Map) {
	m.Load("ParamPage", &x.ParamPage)
	m.Load("vdso", &x.vdso)
	m.Load("os", &x.os)
	m.Load("arch", &x.arch)
	m.LoadValue("phdrs", new([]elfProgHeader), func(y interface{}) { x.loadPhdrs(y.([]elfProgHeader)) })
}

func (x *elfProgHeader) beforeSave() {}
func (x *elfProgHeader) save(m state.Map) {
	x.beforeSave()
	m.Save("Type", &x.Type)
	m.Save("Flags", &x.Flags)
	m.Save("Off", &x.Off)
	m.Save("Vaddr", &x.Vaddr)
	m.Save("Paddr", &x.Paddr)
	m.Save("Filesz", &x.Filesz)
	m.Save("Memsz", &x.Memsz)
	m.Save("Align", &x.Align)
}

func (x *elfProgHeader) afterLoad() {}
func (x *elfProgHeader) load(m state.Map) {
	m.Load("Type", &x.Type)
	m.Load("Flags", &x.Flags)
	m.Load("Off", &x.Off)
	m.Load("Vaddr", &x.Vaddr)
	m.Load("Paddr", &x.Paddr)
	m.Load("Filesz", &x.Filesz)
	m.Load("Memsz", &x.Memsz)
	m.Load("Align", &x.Align)
}

func init() {
	state.Register("loader.byteReader", (*byteReader)(nil), state.Fns{Save: (*byteReader).save, Load: (*byteReader).load})
	state.Register("loader.fileContext", (*fileContext)(nil), state.Fns{Save: (*fileContext).save, Load: (*fileContext).load})
	state.Register("loader.VDSO", (*VDSO)(nil), state.Fns{Save: (*VDSO).save, Load: (*VDSO).load})
	state.Register("loader.elfProgHeader", (*elfProgHeader)(nil), state.Fns{Save: (*elfProgHeader).save, Load: (*elfProgHeader).load})
}
