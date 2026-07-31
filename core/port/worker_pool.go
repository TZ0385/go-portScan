package port

import "sync"

// WorkPool 是给可选增强任务使用的小型有界执行器。
// Submit 故意不阻塞：队列满时应跳过指纹增强，而不能反向拖住开放端口发现。
type WorkPool struct {
	jobs      chan func()
	jobsWG    sync.WaitGroup
	workersWG sync.WaitGroup
	closeOnce sync.Once
}

func NewWorkPool(workers, queueSize int) *WorkPool {
	if workers <= 0 {
		workers = 1
	}
	if queueSize < 0 {
		queueSize = 0
	}
	p := &WorkPool{jobs: make(chan func(), queueSize)}
	p.workersWG.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer p.workersWG.Done()
			for job := range p.jobs {
				job()
				p.jobsWG.Done()
			}
		}()
	}
	return p
}

func (p *WorkPool) TrySubmit(job func()) bool {
	if p == nil || job == nil {
		return false
	}
	p.jobsWG.Add(1)
	select {
	case p.jobs <- job:
		return true
	default:
		p.jobsWG.Done()
		return false
	}
}

func (p *WorkPool) Wait() {
	if p != nil {
		p.jobsWG.Wait()
	}
}

// Close 只能在所有生产者停止后调用；scanner 的 Close/Wait 负责保证这个顺序。
func (p *WorkPool) Close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		p.jobsWG.Wait()
		close(p.jobs)
		p.workersWG.Wait()
	})
}
