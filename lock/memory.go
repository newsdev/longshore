package lock

import (
	"sync"
)

type MemoryLock struct {
	mu     sync.RWMutex
	refMus map[string]*sync.Mutex
}

func NewMemoryLock() *MemoryLock {
	return &MemoryLock{refMus: make(map[string]*sync.Mutex)}
}

func (l *MemoryLock) Lock(key string) {
	var refMu *sync.Mutex

	l.mu.Lock()
	if existingRefMu, ok := l.refMus[key]; ok {
		refMu = existingRefMu
	} else {
		refMu = &sync.Mutex{}
		l.refMus[key] = refMu
	}
	l.mu.Unlock()

	// Aquire the lock on the refference mutext.
	refMu.Lock()
}

func (l *MemoryLock) Unlock(key string) {
	l.mu.RLock()
	l.refMus[key].Unlock()
	l.mu.RUnlock()
}
