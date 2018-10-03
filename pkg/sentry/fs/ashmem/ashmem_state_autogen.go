// automatically generated by stateify.

package ashmem

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *Area) beforeSave() {}
func (x *Area) save(m state.Map) {
	x.beforeSave()
	m.Save("ad", &x.ad)
	m.Save("tmpfsFile", &x.tmpfsFile)
	m.Save("name", &x.name)
	m.Save("size", &x.size)
	m.Save("perms", &x.perms)
	m.Save("pb", &x.pb)
}

func (x *Area) afterLoad() {}
func (x *Area) load(m state.Map) {
	m.Load("ad", &x.ad)
	m.Load("tmpfsFile", &x.tmpfsFile)
	m.Load("name", &x.name)
	m.Load("size", &x.size)
	m.Load("perms", &x.perms)
	m.Load("pb", &x.pb)
}

func (x *Device) beforeSave() {}
func (x *Device) save(m state.Map) {
	x.beforeSave()
	m.Save("unstable", &x.unstable)
}

func (x *Device) afterLoad() {}
func (x *Device) load(m state.Map) {
	m.Load("unstable", &x.unstable)
}

func (x *PinBoard) beforeSave() {}
func (x *PinBoard) save(m state.Map) {
	x.beforeSave()
	m.Save("Set", &x.Set)
}

func (x *PinBoard) afterLoad() {}
func (x *PinBoard) load(m state.Map) {
	m.Load("Set", &x.Set)
}

func (x *Range) beforeSave() {}
func (x *Range) save(m state.Map) {
	x.beforeSave()
	m.Save("Start", &x.Start)
	m.Save("End", &x.End)
}

func (x *Range) afterLoad() {}
func (x *Range) load(m state.Map) {
	m.Load("Start", &x.Start)
	m.Load("End", &x.End)
}

func (x *Set) beforeSave() {}
func (x *Set) save(m state.Map) {
	x.beforeSave()
	var root *SegmentDataSlices = x.saveRoot()
	m.SaveValue("root", root)
}

func (x *Set) afterLoad() {}
func (x *Set) load(m state.Map) {
	m.LoadValue("root", new(*SegmentDataSlices), func(y interface{}) { x.loadRoot(y.(*SegmentDataSlices)) })
}

func (x *node) beforeSave() {}
func (x *node) save(m state.Map) {
	x.beforeSave()
	m.Save("nrSegments", &x.nrSegments)
	m.Save("parent", &x.parent)
	m.Save("parentIndex", &x.parentIndex)
	m.Save("hasChildren", &x.hasChildren)
	m.Save("keys", &x.keys)
	m.Save("values", &x.values)
	m.Save("children", &x.children)
}

func (x *node) afterLoad() {}
func (x *node) load(m state.Map) {
	m.Load("nrSegments", &x.nrSegments)
	m.Load("parent", &x.parent)
	m.Load("parentIndex", &x.parentIndex)
	m.Load("hasChildren", &x.hasChildren)
	m.Load("keys", &x.keys)
	m.Load("values", &x.values)
	m.Load("children", &x.children)
}

func (x *SegmentDataSlices) beforeSave() {}
func (x *SegmentDataSlices) save(m state.Map) {
	x.beforeSave()
	m.Save("Start", &x.Start)
	m.Save("End", &x.End)
	m.Save("Values", &x.Values)
}

func (x *SegmentDataSlices) afterLoad() {}
func (x *SegmentDataSlices) load(m state.Map) {
	m.Load("Start", &x.Start)
	m.Load("End", &x.End)
	m.Load("Values", &x.Values)
}

func init() {
	state.Register("ashmem.Area", (*Area)(nil), state.Fns{Save: (*Area).save, Load: (*Area).load})
	state.Register("ashmem.Device", (*Device)(nil), state.Fns{Save: (*Device).save, Load: (*Device).load})
	state.Register("ashmem.PinBoard", (*PinBoard)(nil), state.Fns{Save: (*PinBoard).save, Load: (*PinBoard).load})
	state.Register("ashmem.Range", (*Range)(nil), state.Fns{Save: (*Range).save, Load: (*Range).load})
	state.Register("ashmem.Set", (*Set)(nil), state.Fns{Save: (*Set).save, Load: (*Set).load})
	state.Register("ashmem.node", (*node)(nil), state.Fns{Save: (*node).save, Load: (*node).load})
	state.Register("ashmem.SegmentDataSlices", (*SegmentDataSlices)(nil), state.Fns{Save: (*SegmentDataSlices).save, Load: (*SegmentDataSlices).load})
}
