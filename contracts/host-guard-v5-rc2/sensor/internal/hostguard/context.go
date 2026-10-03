package hostguard

import "time"

type contextEvent struct {
	at                       time.Time
	peer                     string
	port                     uint16
	start, syn, rst, out, in int64
}
type aggregate struct {
	packets, starts, syn, rst, out, in int64
	ports                              map[uint16]int
}
type contextWindow struct {
	seconds int
	queue   []contextEvent
	head    int
	peers   map[string]*aggregate
	starts  int64
}

func newWindow(seconds int) *contextWindow {
	return &contextWindow{seconds: seconds, peers: map[string]*aggregate{}}
}
func (w *contextWindow) add(e contextEvent) {
	w.queue = append(w.queue, e)
	a := w.peers[e.peer]
	if a == nil {
		a = &aggregate{ports: map[uint16]int{}}
		w.peers[e.peer] = a
	}
	a.packets++
	a.starts += e.start
	a.syn += e.syn
	a.rst += e.rst
	a.out += e.out
	a.in += e.in
	w.starts += e.start
	if e.port > 0 {
		a.ports[e.port]++
	}
}
func (w *contextWindow) advance(at time.Time) {
	cut := at.Add(-time.Duration(w.seconds) * time.Second)
	for w.head < len(w.queue) && !w.queue[w.head].at.After(cut) {
		e := w.queue[w.head]
		a := w.peers[e.peer]
		a.packets--
		a.starts -= e.start
		a.syn -= e.syn
		a.rst -= e.rst
		a.out -= e.out
		a.in -= e.in
		w.starts -= e.start
		if e.port > 0 {
			a.ports[e.port]--
			if a.ports[e.port] == 0 {
				delete(a.ports, e.port)
			}
		}
		if a.packets == 0 {
			delete(w.peers, e.peer)
		}
		w.queue[w.head] = contextEvent{}
		w.head++
	}
	if w.head > 4096 && w.head*2 >= len(w.queue) {
		w.queue = append([]contextEvent(nil), w.queue[w.head:]...)
		w.head = 0
	}
}
func (w *contextWindow) snapshot(peer string, at, coverageStart time.Time) Context {
	w.advance(at)
	c := Context{WindowSeconds: w.seconds, CoverageMs: max(0, min(float64(at.Sub(coverageStart))/float64(time.Millisecond), float64(w.seconds*1000))), HostFlowStarts: w.starts, HostDistinctPeers: len(w.peers)}
	if a := w.peers[peer]; a != nil {
		c.PeerFlowStarts = a.starts
		c.PeerSynCount = a.syn
		c.PeerRstCount = a.rst
		c.PeerDistinctServicePorts = len(a.ports)
		c.PeerBytesOutbound = a.out
		c.PeerBytesInbound = a.in
	}
	return c
}
