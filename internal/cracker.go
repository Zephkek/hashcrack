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
	"edu/hashcrack/pkg/workerpool"
)
// basic definitions for now until we get the dir structure sorted
type Options struct {
	Workers int
	LogPath string
	Event   func(event string, kv map[string]any)
	ProgressEvery uint64 // 50k
  // todo: improve this (generates candidate mutations for a wordlist entry, if nil the input word is used as it is)
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
	if workers <= 0 { workers = runtime.NumCPU() }
	if workers > runtime.NumCPU() { workers = runtime.NumCPU() }
	c.logEvent("start", map[string]any{"workers": workers, "algo": h.Name(), "wordlist": wordlistPath})

	target = strings.ToLower(strings.TrimSpace(target))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var tried uint64
	var found atomic.Bool
	var plaintext atomic.Value

	pool := workerpool.NewStringPool(ctx, workers, func(ctx context.Context, s string) {
		if found.Load() {
			return
		}
		candidates := []string{s}
		if c.opts.Transform != nil {
			if xs := c.opts.Transform(s); len(xs) > 0 { candidates = xs }
		}
		for _, cand := range candidates {
			if found.Load() { return }
			ok, _ := h.Compare(target, cand, p)
			n := atomic.AddUint64(&tried, 1)
			if ok {
				plaintext.Store(cand)
				found.Store(true)
				cancel()
				c.logEvent("found", map[string]any{"candidate": cand, "tried": n})
				return
			}
			every := c.opts.ProgressEvery
			if every == 0 { every = 50000 }
			if n%every == 0 { c.logEvent("progress", map[string]any{"tried": n}) }
		}
	})
	defer pool.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if line == "" {
			continue
		}
		if !pool.Submit(line) {
			break
		}
		if found.Load() {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return res, err
	}

	pool.Close()

	res.Duration = time.Since(start)
	res.Tried = atomic.LoadUint64(&tried)
	if v := plaintext.Load(); v != nil {
		res.Found = true
		res.Plaintext = v.(string)
	}
	c.logEvent("done", map[string]any{"found": res.Found, "tried": res.Tried, "duration_ms": res.Duration.Milliseconds()})
	return res, nil
}

