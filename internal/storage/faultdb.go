package storage

import (
	"errors"
	"sync"
	"syscall"
)

// FaultDB wraps a DB and injects storage faults on demand. It exists for the
// gate-6 fault-injection tests (resource limits must never become consensus
// decisions): a test arms it to fail the next N batch writes (ENOSPC, the
// 2026-08-04 / 2026-09-12 disk-full class), to fail reads of chosen keys (EIO /
// a closed DB), or to panic on a chosen key read (a crash mid-connect). Nothing
// in production constructs one.
type FaultDB struct {
	DB

	mu            sync.Mutex
	failWrites    int
	writeErr      error
	writesFailed  int
	writesOK      int
	failGetKeys   map[string]error
	panicGetKeys  map[string]string
	readsFailed   int
	failAllGets   int
	failAllGetErr error
}

// ErrInjectedENOSPC is the default injected write failure.
var ErrInjectedENOSPC = &injectedErr{msg: "injected write failure", errno: syscall.ENOSPC}

// ErrInjectedEIO is the default injected read failure.
var ErrInjectedEIO = &injectedErr{msg: "injected read failure", errno: syscall.EIO}

type injectedErr struct {
	msg   string
	errno syscall.Errno
}

func (e *injectedErr) Error() string        { return e.msg + ": " + e.errno.Error() }
func (e *injectedErr) Is(target error) bool { return target == e.errno }

// NewFaultDB wraps inner.
func NewFaultDB(inner DB) *FaultDB {
	return &FaultDB{
		DB:           inner,
		failGetKeys:  map[string]error{},
		panicGetKeys: map[string]string{},
	}
}

// FailNextWrites makes the next n batch Write calls fail with err (nil =
// ENOSPC). Nothing in a failed batch is applied (Pebble batches are atomic).
func (f *FaultDB) FailNextWrites(n int, err error) {
	if err == nil {
		err = ErrInjectedENOSPC
	}
	f.mu.Lock()
	f.failWrites = n
	f.writeErr = err
	f.mu.Unlock()
}

// FailGet makes every Get/Has of key fail with err (nil = EIO) until cleared.
func (f *FaultDB) FailGet(key []byte, err error) {
	if err == nil {
		err = ErrInjectedEIO
	}
	f.mu.Lock()
	f.failGetKeys[string(key)] = err
	f.mu.Unlock()
}

// FailNextGets makes the next n Get/Has calls (any key) fail with err.
func (f *FaultDB) FailNextGets(n int, err error) {
	if err == nil {
		err = ErrInjectedEIO
	}
	f.mu.Lock()
	f.failAllGets = n
	f.failAllGetErr = err
	f.mu.Unlock()
}

// PanicOnGet makes a Get/Has of key panic with msg until cleared.
func (f *FaultDB) PanicOnGet(key []byte, msg string) {
	f.mu.Lock()
	f.panicGetKeys[string(key)] = msg
	f.mu.Unlock()
}

// ClearFaults disarms every injection.
func (f *FaultDB) ClearFaults() {
	f.mu.Lock()
	f.failWrites = 0
	f.failAllGets = 0
	f.failGetKeys = map[string]error{}
	f.panicGetKeys = map[string]string{}
	f.mu.Unlock()
}

// WritesFailed / WritesOK / ReadsFailed report how many injections fired.
func (f *FaultDB) WritesFailed() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writesFailed }
func (f *FaultDB) WritesOK() int     { f.mu.Lock(); defer f.mu.Unlock(); return f.writesOK }
func (f *FaultDB) ReadsFailed() int  { f.mu.Lock(); defer f.mu.Unlock(); return f.readsFailed }

func (f *FaultDB) readFault(key []byte) error {
	f.mu.Lock()
	if msg, ok := f.panicGetKeys[string(key)]; ok {
		f.mu.Unlock()
		panic(msg)
	}
	if err, ok := f.failGetKeys[string(key)]; ok {
		f.readsFailed++
		f.mu.Unlock()
		return err
	}
	if f.failAllGets > 0 {
		f.failAllGets--
		f.readsFailed++
		err := f.failAllGetErr
		f.mu.Unlock()
		return err
	}
	f.mu.Unlock()
	return nil
}

func (f *FaultDB) writeFault() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrites > 0 {
		f.failWrites--
		f.writesFailed++
		return f.writeErr
	}
	f.writesOK++
	return nil
}

// Get implements DB.
func (f *FaultDB) Get(key []byte) ([]byte, error) {
	if err := f.readFault(key); err != nil {
		return nil, err
	}
	return f.DB.Get(key)
}

// Has implements DB.
func (f *FaultDB) Has(key []byte) (bool, error) {
	if err := f.readFault(key); err != nil {
		return false, err
	}
	return f.DB.Has(key)
}

// NewBatch implements DB.
func (f *FaultDB) NewBatch() Batch { return &faultBatch{Batch: f.DB.NewBatch(), db: f} }

// NewIndexedBatch implements DB.
func (f *FaultDB) NewIndexedBatch() Batch {
	return &faultBatch{Batch: f.DB.NewIndexedBatch(), db: f}
}

type faultBatch struct {
	Batch
	db *FaultDB
}

func (b *faultBatch) Write() error {
	if err := b.db.writeFault(); err != nil {
		return err
	}
	return b.Batch.Write()
}

func (b *faultBatch) Get(key []byte) ([]byte, error) {
	if err := b.db.readFault(key); err != nil {
		return nil, err
	}
	return b.Batch.Get(key)
}

// IsInjectedFault reports whether err came from a FaultDB injection.
func IsInjectedFault(err error) bool {
	var ie *injectedErr
	return errors.As(err, &ie)
}
