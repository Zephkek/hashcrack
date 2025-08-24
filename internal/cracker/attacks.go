package cracker

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"edu/hashcrack/internal/hashes"
)

type CombinationOptions struct {
	Wordlist1 string
	Wordlist2 string
	Separator string
}

type HybridOptions struct {
	Wordlist string
	Mask     string
	IsPrefix bool // If true, mask+word. If false, word+mask
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

	// Optimized file reading with larger buffers
	words1, err := c.readWordlistOptimized(opts.Wordlist1)
	if err != nil { return res, err }
	
	words2, err := c.readWordlistOptimized(opts.Wordlist2)
	if err != nil { return res, err }

	c.logEvent("wordlist_loaded", map[string]any{
		"wordlist1_count": len(words1),
		"wordlist2_count": len(words2),
		"wordlist1_path": opts.Wordlist1,
		"wordlist2_path": opts.Wordlist2,
	})

	totalCombinations := uint64(len(words1)) * uint64(len(words2))
	
	// Warn about extremely large combination attacks
	if totalCombinations > 100000000 { // 100 million
		c.logEvent("warning", map[string]any{
			"message": "Very large combination attack detected",
			"total_combinations": totalCombinations,
			"wordlist1_size": len(words1),
			"wordlist2_size": len(words2),
			"estimated_time": "This may take an extremely long time to complete",
		})
	}
	
	workers := c.opts.Workers
	if workers <= 0 { workers = runtime.NumCPU() * 2 }
	if workers > runtime.NumCPU() * 4 { workers = runtime.NumCPU() * 4 }

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Optimized work channel with larger buffer
	workChan := make(chan string, workers*32)
	
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
		"total_combinations": totalCombinations,
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
				
				// Optimized progress reporting
				if localTried%5000 == 0 {
					globalCount := atomic.AddUint64(&tried, 5000)
					localTried = 0
					
					every := c.opts.ProgressEvery
					if every == 0 { every = 10000 }
					if globalCount%every == 0 {
						c.logEvent("progress", map[string]any{
							"tried": globalCount,
							"candidate": cand,
							"total": totalCombinations,
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

	// Optimized wordlist reading
	words, err := c.readWordlistOptimized(opts.Wordlist)
	if err != nil { return res, err }

	maskChars := c.generateMaskChars(opts.Mask)
	
	// Calculate total combinations (words * mask combinations)
	maskCombinations := uint64(1)
	for _, chars := range maskChars {
		maskCombinations *= uint64(len(chars))
	}
	totalCombinations := uint64(len(words)) * maskCombinations
	
	workers := c.opts.Workers
	if workers <= 0 { workers = runtime.NumCPU() * 2 }
	if workers > runtime.NumCPU() * 4 { workers = runtime.NumCPU() * 4 }

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Optimized work channel
	workChan := make(chan string, workers*32)
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
		"total_combinations": totalCombinations,
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
				
				// Optimized progress reporting
				if localTried%5000 == 0 {
					globalCount := atomic.AddUint64(&tried, 5000)
					localTried = 0
					
					every := c.opts.ProgressEvery
					if every == 0 { every = 10000 }
					if globalCount%every == 0 {
						c.logEvent("progress", map[string]any{
							"tried": globalCount,
							"candidate": cand,
							"total": totalCombinations,
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
	totalCandidates := uint64(len(candidates))

	workers := c.opts.Workers
	if workers <= 0 { workers = runtime.NumCPU() }
	if workers > runtime.NumCPU() * 2 { workers = runtime.NumCPU() * 2 }

	workChan := make(chan string, 1000)
	var found atomic.Bool
	var plaintext atomic.Value
	var tried uint64
	var wg sync.WaitGroup

	c.logEvent("start", map[string]any{
		"mode": "association",
		"workers": workers,
		"username": opts.Username,
		"total_combinations": totalCandidates,
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
					if every == 0 { every = 5000 }
					if globalCount%every == 0 {
						c.logEvent("progress", map[string]any{
							"tried": globalCount,
							"candidate": cand,
							"total": totalCandidates,
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

// Optimized wordlist reading with larger buffer
func (c *Cracker) readWordlistOptimized(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()

	words := []string{}
	scanner := bufio.NewScanner(f)
	
	// Use larger buffer for better I/O performance
	buf := make([]byte, 0, 2*1024*1024) // 2MB buffer
	scanner.Buffer(buf, 2*1024*1024)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			words = append(words, line)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	
	return words, nil
}

func (c *Cracker) generateMaskChars(mask string) []string {
	var result []string
	for i := 0; i < len(mask); i++ {
		if i+1 < len(mask) && mask[i] == '?' {
			switch mask[i+1] {
			case 'l':
				result = append(result, "abcdefghijklmnopqrstuvwxyz")
				i++
			case 'u':
				result = append(result, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
				i++
			case 'd':
				result = append(result, "0123456789")
				i++
			case 's':
				result = append(result, " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
				i++
			case 'a':
				result = append(result, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
				i++
			default:
				result = append(result, string(mask[i+1]))
				i++
			}
		} else {
			result = append(result, string(mask[i]))
		}
	}
	return result
}

func (c *Cracker) generateHybridCandidates(word string, maskChars []string, isPrefix bool, out chan<- string, ctx context.Context) {
	c.generateHybridRecursive(word, maskChars, 0, "", isPrefix, out, ctx)
}

func (c *Cracker) generateHybridRecursive(word string, maskChars []string, index int, current string, isPrefix bool, out chan<- string, ctx context.Context) {
	if index == len(maskChars) {
		var candidate string
		if isPrefix {
			candidate = current + word
		} else {
			candidate = word + current
		}
		select {
		case out <- candidate:
		case <-ctx.Done():
			return
		}
		return
	}
	
	for _, char := range maskChars[index] {
		c.generateHybridRecursive(word, maskChars, index+1, current+string(char), isPrefix, out, ctx)
	}
}

func (c *Cracker) generateAssociationCandidates(opts AssociationOptions) []string {
	candidates := []string{}
	
	if opts.Username != "" {
		// Basic username variations
		candidates = append(candidates, opts.Username)
		candidates = append(candidates, strings.ToLower(opts.Username))
		candidates = append(candidates, strings.ToUpper(opts.Username))
		candidates = append(candidates, strings.Title(opts.Username))
		
		// Username with common suffixes
		for _, suffix := range []string{"", "1", "12", "123", "1234", "!", "@", "#", "2024", "2025", "99", "00", "01"} {
			candidates = append(candidates, opts.Username+suffix)
			candidates = append(candidates, strings.ToLower(opts.Username)+suffix)
			candidates = append(candidates, strings.ToUpper(opts.Username)+suffix)
		}
		
		// Username with common prefixes
		for _, prefix := range []string{"admin", "user", "test", "demo"} {
			candidates = append(candidates, prefix+opts.Username)
			candidates = append(candidates, prefix+strings.Title(opts.Username))
		}
	}
	
	// Parse email/hint for additional context
	if opts.Hint != "" {
		parts := strings.Split(opts.Hint, "@")
		if len(parts) > 0 {
			localPart := parts[0]
			candidates = append(candidates, localPart)
			candidates = append(candidates, strings.ToLower(localPart))
			
			// Common email-based passwords
			for _, suffix := range []string{"123", "!", "@", "2024", "2025"} {
				candidates = append(candidates, localPart+suffix)
			}
		}
		
		// Use domain name if present
		if len(parts) > 1 {
			domain := strings.Split(parts[1], ".")[0]
			candidates = append(candidates, domain)
			candidates = append(candidates, strings.Title(domain))
			candidates = append(candidates, domain+"123")
		}
	}
	
	// Common passwords based on context
	commonPasswords := []string{
		"password", "Password", "Password1", "Password123",
		"admin", "Admin", "Admin123",
		"qwerty", "123456", "12345678",
		"letmein", "welcome", "Welcome1",
		"changeme", "test", "demo",
	}
	
	if opts.BaseInfo != "" {
		// Add company/base info variations
		candidates = append(candidates, opts.BaseInfo)
		candidates = append(candidates, strings.ToLower(opts.BaseInfo))
		candidates = append(candidates, strings.ToUpper(opts.BaseInfo))
		candidates = append(candidates, strings.Title(opts.BaseInfo))
		
		for _, suffix := range []string{"123", "!", "@", "2024", "2025"} {
			candidates = append(candidates, opts.BaseInfo+suffix)
			candidates = append(candidates, strings.Title(opts.BaseInfo)+suffix)
		}
	}
	
	candidates = append(candidates, commonPasswords...)
	
	// Remove duplicates
	seen := make(map[string]bool)
	unique := []string{}
	for _, c := range candidates {
		if !seen[c] {
			seen[c] = true
			unique = append(unique, c)
		}
	}
	
	return unique
}