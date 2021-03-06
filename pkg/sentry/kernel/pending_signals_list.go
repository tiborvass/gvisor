package kernel

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type pendingSignalElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (pendingSignalElementMapper) linkerFor(elem *pendingSignal) *pendingSignal { return elem }

// List is an intrusive list. Entries can be added to or removed from the list
// in O(1) time and with no additional memory allocations.
//
// The zero value for List is an empty list ready to use.
//
// To iterate over a list (where l is a List):
//      for e := l.Front(); e != nil; e = e.Next() {
// 		// do something with e.
//      }
//
// +stateify savable
type pendingSignalList struct {
	head *pendingSignal
	tail *pendingSignal
}

// Reset resets list l to the empty state.
func (l *pendingSignalList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
func (l *pendingSignalList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
func (l *pendingSignalList) Front() *pendingSignal {
	return l.head
}

// Back returns the last element of list l or nil.
func (l *pendingSignalList) Back() *pendingSignal {
	return l.tail
}

// PushFront inserts the element e at the front of list l.
func (l *pendingSignalList) PushFront(e *pendingSignal) {
	pendingSignalElementMapper{}.linkerFor(e).SetNext(l.head)
	pendingSignalElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		pendingSignalElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
func (l *pendingSignalList) PushBack(e *pendingSignal) {
	pendingSignalElementMapper{}.linkerFor(e).SetNext(nil)
	pendingSignalElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		pendingSignalElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
func (l *pendingSignalList) PushBackList(m *pendingSignalList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		pendingSignalElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		pendingSignalElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}

	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
func (l *pendingSignalList) InsertAfter(b, e *pendingSignal) {
	a := pendingSignalElementMapper{}.linkerFor(b).Next()
	pendingSignalElementMapper{}.linkerFor(e).SetNext(a)
	pendingSignalElementMapper{}.linkerFor(e).SetPrev(b)
	pendingSignalElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		pendingSignalElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
func (l *pendingSignalList) InsertBefore(a, e *pendingSignal) {
	b := pendingSignalElementMapper{}.linkerFor(a).Prev()
	pendingSignalElementMapper{}.linkerFor(e).SetNext(a)
	pendingSignalElementMapper{}.linkerFor(e).SetPrev(b)
	pendingSignalElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		pendingSignalElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
func (l *pendingSignalList) Remove(e *pendingSignal) {
	prev := pendingSignalElementMapper{}.linkerFor(e).Prev()
	next := pendingSignalElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		pendingSignalElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.head = next
	}

	if next != nil {
		pendingSignalElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type pendingSignalEntry struct {
	next *pendingSignal
	prev *pendingSignal
}

// Next returns the entry that follows e in the list.
func (e *pendingSignalEntry) Next() *pendingSignal {
	return e.next
}

// Prev returns the entry that precedes e in the list.
func (e *pendingSignalEntry) Prev() *pendingSignal {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
func (e *pendingSignalEntry) SetNext(elem *pendingSignal) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
func (e *pendingSignalEntry) SetPrev(elem *pendingSignal) {
	e.prev = elem
}
