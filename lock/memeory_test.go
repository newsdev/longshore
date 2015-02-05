package lock

import (
	// "math/rand"
	"testing"
	// "time"
	"sync"
)

func TestMemoryLockUnlock(t *testing.T) {

	l := NewMemoryLock()
	var w sync.WaitGroup

	for i := 0; i < 256; i++ {
		w.Add(1)
		go func() {
			defer w.Done()
			l.Lock("test")
			l.Unlock("test")
		}()
	}
	w.Wait()
}
