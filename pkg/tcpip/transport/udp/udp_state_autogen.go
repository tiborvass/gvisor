// automatically generated by stateify.

package udp

import (
	"gvisor.googlesource.com/gvisor/pkg/state"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
)

func (x *udpPacket) beforeSave() {}
func (x *udpPacket) save(m state.Map) {
	x.beforeSave()
	var data buffer.VectorisedView = x.saveData()
	m.SaveValue("data", data)
	m.Save("udpPacketEntry", &x.udpPacketEntry)
	m.Save("senderAddress", &x.senderAddress)
	m.Save("timestamp", &x.timestamp)
	m.Save("hasTimestamp", &x.hasTimestamp)
}

func (x *udpPacket) afterLoad() {}
func (x *udpPacket) load(m state.Map) {
	m.Load("udpPacketEntry", &x.udpPacketEntry)
	m.Load("senderAddress", &x.senderAddress)
	m.Load("timestamp", &x.timestamp)
	m.Load("hasTimestamp", &x.hasTimestamp)
	m.LoadValue("data", new(buffer.VectorisedView), func(y interface{}) { x.loadData(y.(buffer.VectorisedView)) })
}

func (x *endpoint) save(m state.Map) {
	x.beforeSave()
	var rcvBufSizeMax int = x.saveRcvBufSizeMax()
	m.SaveValue("rcvBufSizeMax", rcvBufSizeMax)
	m.Save("netProto", &x.netProto)
	m.Save("waiterQueue", &x.waiterQueue)
	m.Save("rcvReady", &x.rcvReady)
	m.Save("rcvList", &x.rcvList)
	m.Save("rcvBufSize", &x.rcvBufSize)
	m.Save("rcvClosed", &x.rcvClosed)
	m.Save("rcvTimestamp", &x.rcvTimestamp)
	m.Save("sndBufSize", &x.sndBufSize)
	m.Save("id", &x.id)
	m.Save("state", &x.state)
	m.Save("bindNICID", &x.bindNICID)
	m.Save("regNICID", &x.regNICID)
	m.Save("dstPort", &x.dstPort)
	m.Save("v6only", &x.v6only)
	m.Save("multicastTTL", &x.multicastTTL)
	m.Save("reusePort", &x.reusePort)
	m.Save("shutdownFlags", &x.shutdownFlags)
	m.Save("multicastMemberships", &x.multicastMemberships)
	m.Save("effectiveNetProtos", &x.effectiveNetProtos)
}

func (x *endpoint) load(m state.Map) {
	m.Load("netProto", &x.netProto)
	m.Load("waiterQueue", &x.waiterQueue)
	m.Load("rcvReady", &x.rcvReady)
	m.Load("rcvList", &x.rcvList)
	m.Load("rcvBufSize", &x.rcvBufSize)
	m.Load("rcvClosed", &x.rcvClosed)
	m.Load("rcvTimestamp", &x.rcvTimestamp)
	m.Load("sndBufSize", &x.sndBufSize)
	m.Load("id", &x.id)
	m.Load("state", &x.state)
	m.Load("bindNICID", &x.bindNICID)
	m.Load("regNICID", &x.regNICID)
	m.Load("dstPort", &x.dstPort)
	m.Load("v6only", &x.v6only)
	m.Load("multicastTTL", &x.multicastTTL)
	m.Load("reusePort", &x.reusePort)
	m.Load("shutdownFlags", &x.shutdownFlags)
	m.Load("multicastMemberships", &x.multicastMemberships)
	m.Load("effectiveNetProtos", &x.effectiveNetProtos)
	m.LoadValue("rcvBufSizeMax", new(int), func(y interface{}) { x.loadRcvBufSizeMax(y.(int)) })
	m.AfterLoad(x.afterLoad)
}

func (x *udpPacketList) beforeSave() {}
func (x *udpPacketList) save(m state.Map) {
	x.beforeSave()
	m.Save("head", &x.head)
	m.Save("tail", &x.tail)
}

func (x *udpPacketList) afterLoad() {}
func (x *udpPacketList) load(m state.Map) {
	m.Load("head", &x.head)
	m.Load("tail", &x.tail)
}

func (x *udpPacketEntry) beforeSave() {}
func (x *udpPacketEntry) save(m state.Map) {
	x.beforeSave()
	m.Save("next", &x.next)
	m.Save("prev", &x.prev)
}

func (x *udpPacketEntry) afterLoad() {}
func (x *udpPacketEntry) load(m state.Map) {
	m.Load("next", &x.next)
	m.Load("prev", &x.prev)
}

func init() {
	state.Register("udp.udpPacket", (*udpPacket)(nil), state.Fns{Save: (*udpPacket).save, Load: (*udpPacket).load})
	state.Register("udp.endpoint", (*endpoint)(nil), state.Fns{Save: (*endpoint).save, Load: (*endpoint).load})
	state.Register("udp.udpPacketList", (*udpPacketList)(nil), state.Fns{Save: (*udpPacketList).save, Load: (*udpPacketList).load})
	state.Register("udp.udpPacketEntry", (*udpPacketEntry)(nil), state.Fns{Save: (*udpPacketEntry).save, Load: (*udpPacketEntry).load})
}
