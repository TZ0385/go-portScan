package port

import (
	"sync"
	"testing"
)

func TestWorkPoolRejectsWhenWorkersAndQueueAreFull(t *testing.T) {
	pool := NewWorkPool(1, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	blockingJob := func() {
		once.Do(func() { close(started) })
		<-release
	}
	if !pool.TrySubmit(blockingJob) {
		t.Fatal("first job was rejected")
	}
	<-started
	if !pool.TrySubmit(blockingJob) {
		t.Fatal("queued job was rejected")
	}
	if pool.TrySubmit(func() {}) {
		t.Fatal("expected full pool to reject optional work")
	}
	close(release)
	pool.Close()
}
