package mask

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"encoding/hex"
	"strings"

	"edu/hashcrack/internal/cracker"
	"edu/hashcrack/internal/hashes"
)

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
	radixes []uint64
	startIdx uint64
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
		sets = append(sets, []rune{runes[i]})
		i++
	}
	
	workers := runtime.NumCPU() * 2
	batchSize := 10000
	
	radixes := make([]uint64, len(sets))
	prod := uint64(1)
	for i := len(sets) - 1; i >= 0; i-- {
		radixes[i] = prod
		prod *= uint64(len(sets[i]))
	}
	return &Generator{
		sets: sets,
		workers: workers,
		batchSize: batchSize,
		radixes: radixes,
		startIdx: 0,
	}, nil
}

func (g *Generator) SetStartIndex(idx uint64) {
	g.startIdx = idx
}

func (g *Generator) Crack(ctx context.Context, c *cracker.Cracker, h hashes.Hasher, p hashes.Params, target string) (cracker.Result, error) {
	start := time.Now()
	var res cracker.Result
	var tried uint64

	if g.startIdx > 0 {
		tried = g.startIdx
	}

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
			"resume_index": g.startIdx,
		})
	}

	workChan := make(chan workItem, g.workers*4)
	resultChan := make(chan string, 1)
	
	var wg sync.WaitGroup
	
	var targetDigest []byte
	var byteDigester hashes.ByteDigester
	var runeDigester hashes.RuneDigester
	if bd, ok := h.(hashes.ByteDigester); ok {
		if td, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(target), "0x")); err == nil {
			targetDigest = td
			byteDigester = bd
		}
	}
	if rd, ok := h.(hashes.RuneDigester); ok { runeDigester = rd }

	for i := 0; i < g.workers; i++ {
		wg.Add(1)
		go g.worker(ctx, &wg, workChan, resultChan, h, p, target, targetDigest, byteDigester, runeDigester, &tried, total, eventFunc)
	}

	go g.distributeWorkResumable(ctx, workChan, total)

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
	res.Tried = atomic.LoadUint64(&tried) - g.startIdx
	
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
	targetDigest []byte,
	byteDigester hashes.ByteDigester,
	runeDigester hashes.RuneDigester,
	tried *uint64,
	total uint64,
	eventFunc func(string, map[string]any),
) {
	defer wg.Done()
	
	buf := make([]rune, len(g.sets))
	bufBytes := make([]byte, len(g.sets))
	ascii := true
	for _, set := range g.sets {
		for _, r := range set { if r > 0x7F { ascii = false; break } }
		if !ascii { break }
	}
	localTried := uint64(0)
	progressInterval := uint64(5000)
	
	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-workChan:
			if !ok {
				return
			}
			
			found := g.processWorkItem(item, buf, bufBytes, ascii, h, p, target, targetDigest, byteDigester, runeDigester, &localTried, progressInterval, tried, total, eventFunc)
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
	bufBytes []byte,
	ascii bool,
	h hashes.Hasher,
	p hashes.Params,
	target string,
	targetDigest []byte,
	byteDigester hashes.ByteDigester,
	runeDigester hashes.RuneDigester,
	localTried *uint64,
	progressInterval uint64,
	globalTried *uint64,
	total uint64,
	eventFunc func(string, map[string]any),
) string {
	digits := g.indexToDigitsMask(item.startIndex)
	g.digitsToBufMask(digits, buf)
	attempts := item.endIndex - item.startIndex

	for n := uint64(0); n < attempts; n++ {
		var ok bool
		var candidate string

		if byteDigester != nil && len(targetDigest) > 0 && ascii {
			for j := 0; j < len(buf); j++ { bufBytes[j] = byte(buf[j]) }
			sum, _ := byteDigester.DigestBytes(bufBytes, p)
			ok = len(sum) == len(targetDigest) && constEq(sum, targetDigest)
			if ok { candidate = string(bufBytes) }
		} else if runeDigester != nil {
			sum, _ := runeDigester.DigestRunes(buf, len(buf), p)
			if len(targetDigest) > 0 {
				ok = len(sum) == len(targetDigest) && constEq(sum, targetDigest)
				if ok { candidate = string(buf) }
			} else {
				candidate = string(buf)
				ok, _ = h.Compare(target, candidate, p)
			}
		} else {
			candidate = string(buf)
			ok, _ = h.Compare(target, candidate, p)
		}
		(*localTried)++

		if ok { return candidate }

		if n+1 < attempts {
			changed := g.incrementDigitsMask(digits)
			if changed >= 0 {
				buf[changed] = g.sets[changed][digits[changed]]
				if ascii { bufBytes[changed] = byte(buf[changed]) }
			}
		}

		if *localTried%progressInterval == 0 {
			globalCount := atomic.AddUint64(globalTried, progressInterval)
			if eventFunc != nil {
				progress := float64(globalCount) / float64(total) * 100
				if candidate == "" {
					if ascii { candidate = string(bufBytes) } else { candidate = string(buf) }
				}
				eventFunc("progress", map[string]any{
					"tried": globalCount,
					"total": total,
					"progress_percent": progress,
					"candidate": candidate,
					"index": item.startIndex + n,
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

func (g *Generator) distributeWorkResumable(ctx context.Context, workChan chan<- workItem, total uint64) {
	defer close(workChan)
	
	batchSize := uint64(g.batchSize)
	
	startPoint := uint64(0)
	if g.startIdx > 0 {
		startPoint = g.startIdx
	}
	
	for start := startPoint; start < total; start += batchSize {
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
	for i := 0; i < len(g.sets); i++ {
		setLen := uint64(len(g.sets[i]))
		d := (index / g.radixes[i]) % setLen
		buf[i] = g.sets[i][d]
	}
}

func constEq(a, b []byte) bool {
	if len(a) != len(b) { return false }
	var v byte
	for i := 0; i < len(a); i++ { v |= a[i] ^ b[i] }
	return v == 0
}

func (g *Generator) indexToDigitsMask(index uint64) []int {
	digits := make([]int, len(g.sets))
	for i := 0; i < len(g.sets); i++ {
		setLen := uint64(len(g.sets[i]))
		d := (index / g.radixes[i]) % setLen
		digits[i] = int(d)
	}
	return digits
}

func (g *Generator) digitsToBufMask(digits []int, buf []rune) {
	for i := 0; i < len(digits); i++ { buf[i] = g.sets[i][digits[i]] }
}

func (g *Generator) incrementDigitsMask(digits []int) int {
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i] + 1
		if d < len(g.sets[i]) { digits[i] = d; return i }
		digits[i] = 0
	}
	return -1
}