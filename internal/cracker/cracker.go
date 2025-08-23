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
	"encoding/hex"

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

type ResumableOptions struct {
	StartLine      int64
	CheckpointFunc func(line int64)
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
	return c.CrackWordlistResumable(ctx, h, p, target, wordlistPath, ResumableOptions{})
}

func (c *Cracker) CrackWordlistResumable(ctx context.Context, h hashes.Hasher, p hashes.Params, target string, wordlistPath string, resumeOpts ResumableOptions) (Result, error) {
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
	if workers <= 0 { workers = runtime.NumCPU() * 2 }
	if workers > runtime.NumCPU() * 4 { workers = runtime.NumCPU() * 4 }
	c.logEvent("start", map[string]any{"workers": workers, "algo": h.Name(), "wordlist": wordlistPath, "resume_line": resumeOpts.StartLine})

	target = strings.TrimSpace(target)
	var targetDigest []byte
	var byteDigester hashes.ByteDigester
	if bd, ok := h.(hashes.ByteDigester); ok {
		if td, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(target), "0x")); err == nil {
			targetDigest = td
			byteDigester = bd
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var tried uint64
	var found atomic.Bool
	var plaintext atomic.Value
	var currentLine int64

	// We will use a single scanner below and skip to StartLine once

	workChan := make(chan workItem, workers*8)
	
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
				case work, ok := <-workChan:
					if !ok {
						atomic.AddUint64(&tried, localTried)
						return
					}
					
					if found.Load() {
						continue
					}
					
					candidates := []string{work.word}
					if c.opts.Transform != nil {
						if xs := c.opts.Transform(work.word); len(xs) > 0 { 
							candidates = xs 
						}
					}
					
					if bbd, ok := h.(hashes.BatchByteDigester); ok && len(candidates) >= 4 && byteDigester != nil && len(targetDigest) > 0 {
						batch := make([][]byte, 0, len(candidates))
						for _, cnd := range candidates { batch = append(batch, []byte(cnd)) }
						sums, _ := bbd.DigestMany(batch, p)
						for i, sum := range sums {
							if found.Load() { break }
							ok := len(sum) == len(targetDigest) && constEq(sum, targetDigest)
							localTried++
							if ok {
								plaintext.Store(candidates[i])
								found.Store(true)
								cancel()
								globalCount := atomic.AddUint64(&tried, localTried)
								c.logEvent("found", map[string]any{"candidate": candidates[i], "tried": globalCount})
								return
							}
						}
						if localTried%1000 == 0 {
							globalCount := atomic.AddUint64(&tried, 1000)
							localTried = 0
							every := c.opts.ProgressEvery; if every == 0 { every = 5000 }
							if globalCount%every == 0 { 
								c.logEvent("progress", map[string]any{"tried": globalCount, "line": work.line})
								// Call checkpoint function if provided
								if resumeOpts.CheckpointFunc != nil {
									resumeOpts.CheckpointFunc(work.line)
								}
							}
						}
						continue
					}
					for _, cand := range candidates {
						if found.Load() { 
							break 
						}
						var ok bool
						if byteDigester != nil && len(targetDigest) > 0 {
							sum, _ := byteDigester.DigestBytes([]byte(cand), p)
							ok = len(sum) == len(targetDigest) && constEq(sum, targetDigest)
						} else {
							ok, _ = h.Compare(target, cand, p)
						}
						localTried++
						
						if ok {
							plaintext.Store(cand)
							found.Store(true)
							cancel()
							
							globalCount := atomic.AddUint64(&tried, localTried)
							c.logEvent("found", map[string]any{
								"candidate": cand, 
								"tried": globalCount,
								"line": work.line,
							})
							return
						}
						
						if localTried%1000 == 0 {
							globalCount := atomic.AddUint64(&tried, 1000)
							localTried = 0 
							
							every := c.opts.ProgressEvery
							if every == 0 { every = 5000 }
							if globalCount%every == 0 { 
								c.logEvent("progress", map[string]any{
									"tried": globalCount,
									"candidate": cand,
									"line": work.line,
								})
								// Call checkpoint function if provided
								if resumeOpts.CheckpointFunc != nil {
									resumeOpts.CheckpointFunc(work.line)
								}
							}
						}
					}
				}
			}
		}()
	}

	scanner := bufio.NewScanner(f)
	// Use a larger buffer to reduce Scan overhead on long lines
	buf := make([]byte, 0, 4*1024*1024)
	scanner.Buffer(buf, 4*1024*1024)
	
	// Skip to resume point
	if resumeOpts.StartLine > 0 {
		for i := int64(0); i < resumeOpts.StartLine && scanner.Scan(); i++ {
			currentLine++
		}
	}
	
	// Feed work to workers
	go func() {
		defer close(workChan)
		
		for scanner.Scan() {
			currentLine++
			line := strings.TrimRight(scanner.Text(), "\r\n")
			if line == "" {
				continue
			}
			
			select {
			case workChan <- workItem{word: line, line: currentLine}:
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

type workItem struct {
	word string
	line int64
}

func constEq(a, b []byte) bool {
	if len(a) != len(b) { return false }
	var v byte
	for i := 0; i < len(a); i++ { v |= a[i] ^ b[i] }
	return v == 0
}