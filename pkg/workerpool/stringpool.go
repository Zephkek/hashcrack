package workerpool

import (
	"context"
	"sync"
)

type StringPool struct {
	ctx     context.Context
	cancel  context.CancelFunc
	jobs    chan string
	wg      sync.WaitGroup
	closed  bool
	closeMu sync.Mutex
}

type StringHandler func(ctx context.Context, s string)

func NewStringPool(ctx context.Context, workers int, h StringHandler) *StringPool {
	ctx, cancel := context.WithCancel(ctx)
	p := &StringPool{
		ctx:    ctx,
		cancel: cancel,
		jobs:   make(chan string, workers*2+8),
	}
	p.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-p.ctx.Done():
					return
				case s, ok := <-p.jobs:
					if !ok { return }
					h(p.ctx, s)
				}
			}
		}()
	}
	return p
}

func (p *StringPool) Submit(s string) bool {
	p.closeMu.Lock()
	closed := p.closed
	p.closeMu.Unlock()
	if closed { return false }
	select {
	case <-p.ctx.Done():
		return false
	case p.jobs <- s:
		return true
	}
}

func (p *StringPool) Close() {
	p.closeMu.Lock()
	if p.closed {
		p.closeMu.Unlock()
		return
	}
	p.closed = true
	close(p.jobs)
	p.closeMu.Unlock()
	p.cancel()
	p.wg.Wait()
}
