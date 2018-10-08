// automatically generated by stateify.

package queue

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
)

func (x *Queue) beforeSave() {}
func (x *Queue) save(m state.Map) {
	x.beforeSave()
	m.Save("ReaderQueue", &x.ReaderQueue)
	m.Save("WriterQueue", &x.WriterQueue)
	m.Save("closed", &x.closed)
	m.Save("used", &x.used)
	m.Save("limit", &x.limit)
	m.Save("dataList", &x.dataList)
}

func (x *Queue) afterLoad() {}
func (x *Queue) load(m state.Map) {
	m.Load("ReaderQueue", &x.ReaderQueue)
	m.Load("WriterQueue", &x.WriterQueue)
	m.Load("closed", &x.closed)
	m.Load("used", &x.used)
	m.Load("limit", &x.limit)
	m.Load("dataList", &x.dataList)
}

func init() {
	state.Register("queue.Queue", (*Queue)(nil), state.Fns{Save: (*Queue).save, Load: (*Queue).load})
}