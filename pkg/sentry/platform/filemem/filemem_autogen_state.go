// automatically generated by stateify.

package filemem

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *FileMem) beforeSave() {}
func (x *FileMem) save(m state.Map) {
	x.beforeSave()
	m.Save("file", &x.file)
	m.Save("mu", &x.mu)
	m.Save("usage", &x.usage)
	m.Save("usageExpected", &x.usageExpected)
	m.Save("usageSwapped", &x.usageSwapped)
	m.Save("usageLast", &x.usageLast)
	m.Save("fileSize", &x.fileSize)
	m.Save("destroyed", &x.destroyed)
	m.Save("reclaimable", &x.reclaimable)
	m.Save("reclaimCond", &x.reclaimCond)
	m.Save("mappingsMu", &x.mappingsMu)
	m.Save("mappings", &x.mappings)
}

func (x *FileMem) afterLoad() {}
func (x *FileMem) load(m state.Map) {
	m.Load("file", &x.file)
	m.Load("mu", &x.mu)
	m.Load("usage", &x.usage)
	m.Load("usageExpected", &x.usageExpected)
	m.Load("usageSwapped", &x.usageSwapped)
	m.Load("usageLast", &x.usageLast)
	m.Load("fileSize", &x.fileSize)
	m.Load("destroyed", &x.destroyed)
	m.Load("reclaimable", &x.reclaimable)
	m.Load("reclaimCond", &x.reclaimCond)
	m.Load("mappingsMu", &x.mappingsMu)
	m.Load("mappings", &x.mappings)
}

func (x *usageInfo) beforeSave() {}
func (x *usageInfo) save(m state.Map) {
	x.beforeSave()
	m.Save("kind", &x.kind)
	m.Save("knownCommitted", &x.knownCommitted)
	m.Save("refs", &x.refs)
}

func (x *usageInfo) afterLoad() {}
func (x *usageInfo) load(m state.Map) {
	m.Load("kind", &x.kind)
	m.Load("knownCommitted", &x.knownCommitted)
	m.Load("refs", &x.refs)
}

func (x *usageSetFunctions) beforeSave() {}
func (x *usageSetFunctions) save(m state.Map) {
	x.beforeSave()
}

func (x *usageSetFunctions) afterLoad() {}
func (x *usageSetFunctions) load(m state.Map) {
}

func (x *usageSet) beforeSave() {}
func (x *usageSet) save(m state.Map) {
	x.beforeSave()
	var root *usageSegmentDataSlices = x.saveRoot()
	m.SaveValue("root", root)
}

func (x *usageSet) afterLoad() {}
func (x *usageSet) load(m state.Map) {
	m.LoadValue("root", new(*usageSegmentDataSlices), func(y interface{}) { x.loadRoot(y.(*usageSegmentDataSlices)) })
}

func (x *usagenode) beforeSave() {}
func (x *usagenode) save(m state.Map) {
	x.beforeSave()
	m.Save("nrSegments", &x.nrSegments)
	m.Save("parent", &x.parent)
	m.Save("parentIndex", &x.parentIndex)
	m.Save("hasChildren", &x.hasChildren)
	m.Save("keys", &x.keys)
	m.Save("values", &x.values)
	m.Save("children", &x.children)
}

func (x *usagenode) afterLoad() {}
func (x *usagenode) load(m state.Map) {
	m.Load("nrSegments", &x.nrSegments)
	m.Load("parent", &x.parent)
	m.Load("parentIndex", &x.parentIndex)
	m.Load("hasChildren", &x.hasChildren)
	m.Load("keys", &x.keys)
	m.Load("values", &x.values)
	m.Load("children", &x.children)
}

func (x *usageIterator) beforeSave() {}
func (x *usageIterator) save(m state.Map) {
	x.beforeSave()
	m.Save("node", &x.node)
	m.Save("index", &x.index)
}

func (x *usageIterator) afterLoad() {}
func (x *usageIterator) load(m state.Map) {
	m.Load("node", &x.node)
	m.Load("index", &x.index)
}

func (x *usageGapIterator) beforeSave() {}
func (x *usageGapIterator) save(m state.Map) {
	x.beforeSave()
	m.Save("node", &x.node)
	m.Save("index", &x.index)
}

func (x *usageGapIterator) afterLoad() {}
func (x *usageGapIterator) load(m state.Map) {
	m.Load("node", &x.node)
	m.Load("index", &x.index)
}

func (x *usageSegmentDataSlices) beforeSave() {}
func (x *usageSegmentDataSlices) save(m state.Map) {
	x.beforeSave()
	m.Save("Start", &x.Start)
	m.Save("End", &x.End)
	m.Save("Values", &x.Values)
}

func (x *usageSegmentDataSlices) afterLoad() {}
func (x *usageSegmentDataSlices) load(m state.Map) {
	m.Load("Start", &x.Start)
	m.Load("End", &x.End)
	m.Load("Values", &x.Values)
}

func init() {
	state.Register("filemem.FileMem", (*FileMem)(nil), state.Fns{Save: (*FileMem).save, Load: (*FileMem).load})
	state.Register("filemem.usageInfo", (*usageInfo)(nil), state.Fns{Save: (*usageInfo).save, Load: (*usageInfo).load})
	state.Register("filemem.usageSetFunctions", (*usageSetFunctions)(nil), state.Fns{Save: (*usageSetFunctions).save, Load: (*usageSetFunctions).load})
	state.Register("filemem.usageSet", (*usageSet)(nil), state.Fns{Save: (*usageSet).save, Load: (*usageSet).load})
	state.Register("filemem.usagenode", (*usagenode)(nil), state.Fns{Save: (*usagenode).save, Load: (*usagenode).load})
	state.Register("filemem.usageIterator", (*usageIterator)(nil), state.Fns{Save: (*usageIterator).save, Load: (*usageIterator).load})
	state.Register("filemem.usageGapIterator", (*usageGapIterator)(nil), state.Fns{Save: (*usageGapIterator).save, Load: (*usageGapIterator).load})
	state.Register("filemem.usageSegmentDataSlices", (*usageSegmentDataSlices)(nil), state.Fns{Save: (*usageSegmentDataSlices).save, Load: (*usageSegmentDataSlices).load})
}