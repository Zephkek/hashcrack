package cracker

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"edu/hashcrack/internal/hashes"
)

type AttackMode int

const (
	Straight AttackMode = iota
	Combination
	BruteForce
	HybridDictMask
	HybridMaskDict
	Association
)

type CombinationOptions struct {
	Wordlist1 string
	Wordlist2 string
	Separator string
}

type HybridOptions struct {
	Wordlist string
	Mask     string
	IsPrefix bool
}

type AssociationOptions struct {
	Username string
	Hint     string
	Filename string
	BaseInfo string
}

func (c *Cracker) CrackCombination(ctx context.Context, h hashes.Hasher, p hashes.Params, target string, opts CombinationOptions) (Result, error) {
	start := time.Now()
	res := Result{}

	f1, err := os.Open(opts.Wordlist1)
	if err != nil { return res, err }
	defer f1.Close()

	f2, err := os.Open(opts.Wordlist2)
	if err != nil { return res, err }
	defer f2.Close()

	words1 := []string{}
	scanner1 := bufio.NewScanner(f1)
	for scanner1.Scan() {
		words1 = append(words1, strings.TrimSpace(scanner1.Text()))
	}

	words2 := []string{}
	scanner2 := bufio.NewScanner(f2)
	for scanner2.Scan() {
		words2 = append(words2, strings.TrimSpace(scanner2.Text()))
	}

	workers := c.opts.Workers
	if workers <= 0 { workers = 8 }

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workChan := make(chan string, 1000)
	var found atomic.Bool
	var plaintext atomic.Value
	var tried uint64
	var wg sync.WaitGroup

	c.logEvent("start", map[string]any{
		"mode": "combination",
		"workers": workers,
		"wordlist1": opts.Wordlist1,
		"wordlist2": opts.Wordlist2,
		"separator": opts.Separator,
	})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localTried := uint64(0)
			for cand := range workChan {
				if found.Load() { return }
				localTried++
				
				if match, _ := h.Compare(target, cand, p); match {
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
				
				if localTried%1000 == 0 {
					globalCount := atomic.AddUint64(&tried, 1000)
					localTried = 0
					
					every := c.opts.ProgressEvery
					if every == 0 { every = 10000 }
					if globalCount%every == 0 {
						c.logEvent("progress", map[string]any{
							"tried": globalCount,
							"candidate": cand,
						})
					}
				}
			}
		}()
	}

	go func() {
		defer close(workChan)
		for _, w1 := range words1 {
			if found.Load() { return }
			for _, w2 := range words2 {
				if found.Load() { return }
				
				combined := w1 + opts.Separator + w2
				select {
				case workChan <- combined:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	wg.Wait()

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

func (c *Cracker) CrackHybrid(ctx context.Context, h hashes.Hasher, p hashes.Params, target string, opts HybridOptions) (Result, error) {
	start := time.Now()
	res := Result{}

	f, err := os.Open(opts.Wordlist)
	if err != nil { return res, err }
	defer f.Close()

	words := []string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		words = append(words, strings.TrimSpace(scanner.Text()))
	}

	maskChars := c.generateMaskChars(opts.Mask)
	
	workers := c.opts.Workers
	if workers <= 0 { workers = 8 }

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workChan := make(chan string, 1000)
	var found atomic.Bool
	var plaintext atomic.Value
	var tried uint64
	var wg sync.WaitGroup

	c.logEvent("start", map[string]any{
		"mode": "hybrid",
		"workers": workers,
		"wordlist": opts.Wordlist,
		"mask": opts.Mask,
		"is_prefix": opts.IsPrefix,
	})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localTried := uint64(0)
			for cand := range workChan {
				if found.Load() { return }
				localTried++
				
				if match, _ := h.Compare(target, cand, p); match {
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
				
				if localTried%1000 == 0 {
					globalCount := atomic.AddUint64(&tried, 1000)
					localTried = 0
					
					every := c.opts.ProgressEvery
					if every == 0 { every = 10000 }
					if globalCount%every == 0 {
						c.logEvent("progress", map[string]any{
							"tried": globalCount,
							"candidate": cand,
						})
					}
				}
			}
		}()
	}

	go func() {
		defer close(workChan)
		for _, word := range words {
			if found.Load() { return }
			c.generateHybridCandidates(word, maskChars, opts.IsPrefix, workChan, ctx)
		}
	}()

	wg.Wait()

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

func (c *Cracker) CrackAssociation(ctx context.Context, h hashes.Hasher, p hashes.Params, target string, opts AssociationOptions) (Result, error) {
	start := time.Now()
	res := Result{}

	candidates := c.generateAssociationCandidates(opts)
	
	workers := c.opts.Workers
	if workers <= 0 { workers = 8 }

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workChan := make(chan string, 1000)
	var found atomic.Bool
	var plaintext atomic.Value
	var tried uint64
	var wg sync.WaitGroup

	c.logEvent("start", map[string]any{
		"mode": "association",
		"workers": workers,
		"username": opts.Username,
		"hint": opts.Hint,
		"filename": opts.Filename,
		"candidates": len(candidates),
	})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localTried := uint64(0)
			for cand := range workChan {
				if found.Load() { return }
				localTried++
				
				if match, _ := h.Compare(target, cand, p); match {
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
				
				if localTried%100 == 0 {
					globalCount := atomic.AddUint64(&tried, 100)
					localTried = 0
					
					every := c.opts.ProgressEvery
					if every == 0 { every = 1000 }
					if globalCount%every == 0 {
						c.logEvent("progress", map[string]any{
							"tried": globalCount,
							"candidate": cand,
						})
					}
				}
			}
		}()
	}

	go func() {
		defer close(workChan)
		for _, cand := range candidates {
			if found.Load() { return }
			select {
			case workChan <- cand:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()

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

func (c *Cracker) generateMaskChars(mask string) [][]rune {
	chars := [][]rune{}
	runes := []rune(mask)
	
	for i := 0; i < len(runes); {
		if runes[i] == '?' && i+1 < len(runes) {
			switch runes[i+1] {
			case 'l':
				chars = append(chars, []rune("abcdefghijklmnopqrstuvwxyz"))
			case 'u':
				chars = append(chars, []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
			case 'd':
				chars = append(chars, []rune("0123456789"))
			case 's':
				chars = append(chars, []rune("!@#$%^&*()-_=+[]{};:'\",.<>/?|`~"))
			}
			i += 2
		} else {
			chars = append(chars, []rune{runes[i]})
			i++
		}
	}
	
	return chars
}

func (c *Cracker) generateHybridCandidates(word string, maskChars [][]rune, isPrefix bool, workChan chan<- string, ctx context.Context) {
	total := 1
	for _, chars := range maskChars {
		total *= len(chars)
	}
	
	for i := 0; i < total; i++ {
		if ctx.Err() != nil { return }
		
		maskPart := ""
		temp := i
		for _, chars := range maskChars {
			maskPart = string(chars[temp%len(chars)]) + maskPart
			temp /= len(chars)
		}
		
		var candidate string
		if isPrefix {
			candidate = maskPart + word
		} else {
			candidate = word + maskPart
		}
		
		select {
		case workChan <- candidate:
		case <-ctx.Done():
			return
		}
	}
}

func (c *Cracker) generateAssociationCandidates(opts AssociationOptions) []string {
	candidates := []string{}
	
	base := []string{}
	if opts.Username != "" { base = append(base, opts.Username) }
	if opts.Hint != "" { base = append(base, opts.Hint) }
	if opts.Filename != "" { base = append(base, opts.Filename) }
	if opts.BaseInfo != "" { base = append(base, opts.BaseInfo) }
	
	years := []string{"2024", "2023", "2022", "2021", "2020", "123", "1234", "12345"}
	numbers := []string{"", "1", "12", "123", "1234", "01", "001"}
	symbols := []string{"", "!", "@", "#", "$", "!@", "123", "321"}
	
	for _, b := range base {
		candidates = append(candidates, b)
		candidates = append(candidates, strings.ToLower(b))
		candidates = append(candidates, strings.ToUpper(b))
		candidates = append(candidates, strings.Title(b))
		
		for _, y := range years {
			candidates = append(candidates, b+y)
			candidates = append(candidates, y+b)
			candidates = append(candidates, strings.ToLower(b)+y)
			candidates = append(candidates, strings.ToUpper(b)+y)
		}
		
		for _, n := range numbers {
			candidates = append(candidates, b+n)
			candidates = append(candidates, n+b)
		}
		
		for _, s := range symbols {
			candidates = append(candidates, b+s)
			candidates = append(candidates, s+b)
		}
		
		candidates = append(candidates, b+b)
		candidates = append(candidates, strings.Repeat(b, 2))
		candidates = append(candidates, strings.Repeat(b, 3))
	}
	
	return c.removeDuplicates(candidates)
}

func (c *Cracker) removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, v := range slice {
		if !seen[v] && v != "" {
			seen[v] = true
			result = append(result, v)
		}
	}
	
	return result
}
