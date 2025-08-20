package mask

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"edu/hashcrack/internal/cracker"
	"edu/hashcrack/internal/hashes"
)

// Mask tokens: ?l lower, ?u upper, ?d digits, ?s specials
var (
	lower   = []rune("abcdefghijklmnopqrstuvwxyz")
	upper   = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	digits  = []rune("0123456789")
	special = []rune("!@#$%^&*()-_=+[]{};:'\",.<>/?|`~")
)

type Generator struct { 
	sets [][]rune 
	workers int
	batchSize int
}

type workItem struct {
	startIndex uint64
	endIndex   uint64
}

func NewGenerator(pattern string) (*Generator, error) {
	if pattern == "" { return nil, errors.New("mask required") }
	runes := []rune(pattern)
	sets := make([][]rune, 0, len(runes)/2)
	for i := 0; i < len(runes); {
		if runes[i] == '?' {
			if i+1 >= len(runes) { return nil, errors.New("dangling ? in mask") }
			switch runes[i+1] {
			case 'l': sets = append(sets, lower)
			case 'u': sets = append(sets, upper)
			case 'd': sets = append(sets, digits)
			case 's': sets = append(sets, special)
			default:
				return nil, errors.New("unknown mask token")
			}
			i += 2
			continue
		}
		// literal char 
		sets = append(sets, []rune{runes[i]})
		i++
	}
	
	workers := runtime.NumCPU() * 2 // idk, more ig?
	batchSize := 10000 // larger = better performance, still technically slow compared to just using gpu but who cares now
	
	return &Generator{
		sets: sets, 
		workers: workers,
		batchSize: batchSize,
	}, nil
}

func (g *Generator) Crack(ctx context.Context, c *cracker.Cracker, h hashes.Hasher, p hashes.Params, target string) (cracker.Result, error) {
	start := time.Now()
	var res cracker.Result
	var tried uint64

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	total := uint64(1)
	for _, set := range g.sets {
		total *= uint64(len(set))
	}

	eventFunc := c.GetEventFunc()
	if eventFunc != nil {
		eventFunc("start", map[string]any{
			"mode": "mask",
			"pattern": "mask",
			"total_combinations": total,
			"workers": g.workers,
		})
	}

	workChan := make(chan workItem, g.workers*4)
	resultChan := make(chan string, 1)
  // sync waitgroup!!!
	var wg sync.WaitGroup
	for i := 0; i < g.workers; i++ {
		wg.Add(1)
		go g.worker(ctx, &wg, workChan, resultChan, h, p, target, &tried, total, eventFunc)
	}

	// wwww ywaza3!!
	go g.distributeWork(ctx, workChan, total)

  // el bolis
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var found string
	select {
	case found = <-resultChan:
		if found != "" {
			res.Found = true
			res.Plaintext = found
		}
		cancel() 
	case <-ctx.Done():
	}

	wg.Wait()

	res.Duration = time.Since(start)
	res.Tried = atomic.LoadUint64(&tried)
	
	if eventFunc != nil {
		eventFunc("done", map[string]any{
			"found": res.Found,
			"tried": res.Tried,
			"duration_ms": res.Duration.Milliseconds(),
			"total_combinations": total,
		})
	}
	
	return res, nil
}

func (g *Generator) worker(
	ctx context.Context,
	wg *sync.WaitGroup,
	workChan <-chan workItem,
	resultChan chan<- string,
	h hashes.Hasher,
	p hashes.Params,
	target string,
	tried *uint64,
	total uint64,
	eventFunc func(string, map[string]any),
) {
	defer wg.Done()
	
	buf := make([]rune, len(g.sets)) 
	localTried := uint64(0)
	progressInterval := uint64(5000) // Report progress every 5000 attempts
	
	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-workChan:
			if !ok {
				return
			}
			
			found := g.processWorkItem(item, buf, h, p, target, &localTried, progressInterval, tried, total, eventFunc)
			if found != "" {
				select {
				case resultChan <- found:
				case <-ctx.Done():
				}
				return
			}
		}
	}
}

func (g *Generator) processWorkItem(
	item workItem,
	buf []rune,
	h hashes.Hasher,
	p hashes.Params,
	target string,
	localTried *uint64,
	progressInterval uint64,
	globalTried *uint64,
	total uint64,
	eventFunc func(string, map[string]any),
) string {
	
	for i := item.startIndex; i < item.endIndex; i++ {
		g.indexToCombination(i, buf)
		candidate := string(buf)
		
	ok, _ := h.Compare(target, candidate, p)
	(*localTried)++
		
		if ok {
			return candidate
		}
		
		if *localTried%progressInterval == 0 {
			globalCount := atomic.AddUint64(globalTried, progressInterval)
			if eventFunc != nil {
				progress := float64(globalCount) / float64(total) * 100
				eventFunc("progress", map[string]any{
					"tried": globalCount,
					"total": total,
					"progress_percent": progress,
					"candidate": candidate,
				})
			}
		}
	}
	
	if remaining := *localTried % progressInterval; remaining > 0 {
		atomic.AddUint64(globalTried, remaining)
	}
	
	return ""
}

func (g *Generator) distributeWork(ctx context.Context, workChan chan<- workItem, total uint64) {
	defer close(workChan)
	
	batchSize := uint64(g.batchSize)
	for start := uint64(0); start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		
		item := workItem{
			startIndex: start,
			endIndex:   end,
		}
		
		select {
		case workChan <- item:
		case <-ctx.Done():
			return
		}
	}
}

func (g *Generator) indexToCombination(index uint64, buf []rune) {
	for i := len(g.sets) - 1; i >= 0; i-- {
		setLen := uint64(len(g.sets[i]))
		buf[i] = g.sets[i][index%setLen]
		index /= setLen
	}
}
