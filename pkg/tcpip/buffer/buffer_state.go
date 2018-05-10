// automatically generated by stateify.

package buffer

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *View) save(m state.Map) {
	m.SaveValue("", ([]byte)(*x))
}

func (x *View) load(m state.Map) {
	m.LoadValue("", new([]byte), func(y interface{}) { *x = (View)(y.([]byte)) })
}

func (x *VectorisedView) beforeSave() {}
func (x *VectorisedView) save(m state.Map) {
	x.beforeSave()
	m.Save("views", &x.views)
	m.Save("size", &x.size)
}

func (x *VectorisedView) afterLoad() {}
func (x *VectorisedView) load(m state.Map) {
	m.Load("views", &x.views)
	m.Load("size", &x.size)
}

func init() {
	state.Register("buffer.View", (*View)(nil), state.Fns{Save: (*View).save, Load: (*View).load})
	state.Register("buffer.VectorisedView", (*VectorisedView)(nil), state.Fns{Save: (*VectorisedView).save, Load: (*VectorisedView).load})
}
