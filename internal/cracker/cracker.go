package cracker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"edu/hashcrack/internal/hashes"
)

type Options struct {
	Workers int
	LogPath string
	Event   func(event string, kv map[string]any)
	ProgressEvery uint64 
	Transform func(string) []string
}

type Result struct {
	Found     bool          `json:"found"`
	Plaintext string        `json:"plaintext"`
	Tried     uint64        `json:"tried"`
	Duration  time.Duration `json:"duration_ns"`
}

type Cracker struct {
	opts    Options
	logMu   sync.Mutex
	logFile *os.File
}

func New(opts Options) *Cracker {
	c := &Cracker{opts: opts}
	if opts.LogPath != "" {
		if f, err := os.Create(opts.LogPath); err == nil {
			c.logFile = f
		}
	}
	return c
}

func (c *Cracker) Close() error {
	if c.logFile != nil {
		return c.logFile.Close()
	}
	return nil
}

func (c *Cracker) GetEventFunc() func(string, map[string]any) {
	return c.logEvent
}

func (c *Cracker) logEvent(event string, kv map[string]any) {
	rec := map[string]any{"ts": time.Now().Format(time.RFC3339Nano), "event": event}
	for k, v := range kv { rec[k] = v }
	if c.logFile != nil {
		b, _ := json.Marshal(rec)
		c.logMu.Lock()
		_, _ = c.logFile.Write(append(b, '\n'))
		c.logMu.Unlock()
	}
	if c.opts.Event != nil {
		c.opts.Event(event, rec)
	}
}

func (c *Cracker) CrackWordlist(ctx context.Context, h hashes.Hasher, p hashes.Params, target string, wordlistPath string) (Result, error) {
	start := time.Now()
	res := Result{}

	if wordlistPath == "" {
		return res, errors.New("wordlist required")
	}
	f, err := os.Open(wordlistPath)
	if err != nil {
		return res, err
	}
	defer f.Close()

	workers := c.opts.Workers
	if workers <= 0 { workers = runtime.NumCPU() * 2 } // 5adema... barcha 5adema
	if workers > runtime.NumCPU() * 4 { workers = runtime.NumCPU() * 4 } // cap at 4x CPU cores so it isn't excessive 
	c.logEvent("start", map[string]any{"workers": workers, "algo": h.Name(), "wordlist": wordlistPath})

	target = strings.TrimSpace(target)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var tried uint64
	var found atomic.Bool
	var plaintext atomic.Value

	workChan := make(chan string, workers*8)
	
	// added: sync.WaitGroup  per worker
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localTried := uint64(0)
			
			for {
				select {
				case <-ctx.Done():
					atomic.AddUint64(&tried, localTried)
					return
				case word, ok := <-workChan:
					if !ok {
						atomic.AddUint64(&tried, localTried)
						return
					}
					
					if found.Load() {
						continue
					}
					
					candidates := []string{word}
					if c.opts.Transform != nil {
						if xs := c.opts.Transform(word); len(xs) > 0 { 
							candidates = xs 
						}
					}
					
					for _, cand := range candidates {
						if found.Load() { 
							break 
						}
						
						ok, _ := h.Compare(target, cand, p)
						localTried++
						
						if ok {
							plaintext.Store(cand)
							found.Store(true)
							cancel()
							
							globalCount := atomic.AddUint64(&tried, localTried)
							c.logEvent("found", map[string]any{
								"candidate": cand, 
								"tried": globalCount,
							})
							return
						}
						// batch them all and process
						if localTried%1000 == 0 {
							globalCount := atomic.AddUint64(&tried, 1000)
							localTried = 0 
							
							every := c.opts.ProgressEvery
							if every == 0 { every = 50000 }
							if globalCount%every == 0 { 
								c.logEvent("progress", map[string]any{
									"tried": globalCount,
									"candidate": cand,
								}) 
							}
						}
					}
				}
			}
		}()
	}

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 2*1024*1024) // 2MB buffer
	scanner.Buffer(buf, 2*1024*1024)
	
	// Feed work to workers
	go func() {
		defer close(workChan)
		
		for scanner.Scan() {
			line := strings.TrimRight(scanner.Text(), "\r\n")
			if line == "" {
				continue
			}
			
			select {
			case workChan <- line:
			case <-ctx.Done():
				return
			}
			
			if found.Load() {
				break
			}
		}
	}()

	wg.Wait()

	if err := scanner.Err(); err != nil {
		return res, err
	}

	res.Duration = time.Since(start)
	res.Tried = atomic.LoadUint64(&tried)
	if v := plaintext.Load(); v != nil {
		res.Found = true
		res.Plaintext = v.(string)
	}
	c.logEvent("done", map[string]any{
		"found": res.Found, 
		"tried": res.Tried, 
		"duration_ms": res.Duration.Milliseconds(),
	})
	return res, nil
}
