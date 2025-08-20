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
