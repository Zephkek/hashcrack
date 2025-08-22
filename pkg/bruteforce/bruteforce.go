package bruteforce

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"strings"
	"encoding/hex"

	"edu/hashcrack/internal/hashes"
)

type ConcurrentBruteForcer struct {
	charset   []rune
	minLen    int
	maxLen    int
	workers   int
	batchSize int
	startIdx  uint64  // Resume support
}

type Result struct {
	Found     bool
	Plaintext string
	Tried     uint64
	Duration  time.Duration
}

type ProgressCallback func(tried uint64, total uint64, candidate string, currentLength int)

func New(charset string, minLen, maxLen, workers int) *ConcurrentBruteForcer {
	if workers <= 0 {
		workers = runtime.NumCPU() * 2
	}
	
	batchSize := 5000
	if maxLen <= 4 {
		batchSize = 20000
	} else if maxLen <= 6 {
		batchSize = 10000
	} else if maxLen >= 8 {
		batchSize = 20000
	}
	
	return &ConcurrentBruteForcer{
		charset:   []rune(charset),
		minLen:    minLen,
		maxLen:    maxLen,
		workers:   workers,
		batchSize: batchSize,
		startIdx:  0,
	}
}

// SetStartIndex sets the starting index for resuming
func (bf *ConcurrentBruteForcer) SetStartIndex(idx uint64) {
	bf.startIdx = idx
}

func (bf *ConcurrentBruteForcer) Crack(ctx context.Context, hasher hashes.Hasher, params hashes.Params, target string, progressCb ProgressCallback) (Result, error) {
	start := time.Now()
	var result Result
	var tried uint64
	
	total := bf.calculateTotal()

	// Adjust tried count if resuming
	if bf.startIdx > 0 {
		tried = bf.startIdx
	}

	var targetDigest []byte
	var byteDigester hashes.ByteDigester
	var runeDigester hashes.RuneDigester
	var batchDigester hashes.BatchByteDigester
	if bd, ok := hasher.(hashes.ByteDigester); ok {
		if td, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(target), "0x")); err == nil {
			targetDigest = td
			byteDigester = bd
		}
	}
	if rd, ok := hasher.(hashes.RuneDigester); ok {
		runeDigester = rd
	}
	if bbd, ok := hasher.(hashes.BatchByteDigester); ok {
		batchDigester = bbd
	}

	workChan := make(chan workItem, bf.workers*4)
	resultChan := make(chan string, 1)
	
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	var wg sync.WaitGroup
	for i := 0; i < bf.workers; i++ {
		wg.Add(1)
		go bf.worker(ctx, &wg, workChan, resultChan, hasher, params, target, targetDigest, byteDigester, runeDigester, batchDigester, &tried, total, progressCb)
	}

	go bf.distributeWorkResumable(ctx, workChan, total)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	select {
	case found := <-resultChan:
		if found != "" {
			result.Found = true
			result.Plaintext = found
		}
		cancel() 
	case <-ctx.Done():
	}
	
	wg.Wait()
	
	result.Tried = atomic.LoadUint64(&tried) - bf.startIdx
	result.Duration = time.Since(start)
	
	return result, nil
}

type workItem struct {
	startIndex uint64
	endIndex   uint64
	length     int
}

func (bf *ConcurrentBruteForcer) worker(
	ctx context.Context,
	wg *sync.WaitGroup,
	workChan <-chan workItem,
	resultChan chan<- string,
	hasher hashes.Hasher,
	params hashes.Params,
	target string,
	targetDigest []byte,
	byteDigester hashes.ByteDigester,
	runeDigester hashes.RuneDigester,
	batchDigester hashes.BatchByteDigester,
	tried *uint64,
	total uint64,
	progressCb ProgressCallback,
) {
	defer wg.Done()

	bufRunes := make([]rune, bf.maxLen)
	bufBytes := make([]byte, bf.maxLen)
	asciiCharset := bf.isASCIICharset()
	localPending := uint64(0)
	progressInterval := uint64(2000)
	algoName := hasher.Name()
	algoLower := strings.ToLower(algoName)
	switch {
	case algoLower == "bcrypt":
		progressInterval = 50
	case algoLower == "scrypt":
		progressInterval = 100
	case strings.Contains(algoLower, "argon"):
		progressInterval = 100
	case total <= 100_000:
		progressInterval = 500
	case total <= 5_000_000:
		progressInterval = 2_000
	default:
		progressInterval = 5_000
	}
	
	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-workChan:
			if !ok {
				return
			}
			
			found := bf.processWorkItem(item, bufRunes, bufBytes, asciiCharset, hasher, params, target, targetDigest, byteDigester, runeDigester, batchDigester, &localPending, progressInterval, tried, total, progressCb)
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

func (bf *ConcurrentBruteForcer) processWorkItem(
	item workItem,
	bufRunes []rune,
	bufBytes []byte,
	asciiCharset bool,
	hasher hashes.Hasher,
	params hashes.Params,
	target string,
	targetDigest []byte,
	byteDigester hashes.ByteDigester,
	runeDigester hashes.RuneDigester,
	batchDigester hashes.BatchByteDigester,
	localPending *uint64,
	progressInterval uint64,
	globalTried *uint64,
	total uint64,
	progressCb ProgressCallback,
) string {
	digits := bf.indexToDigits(item.startIndex, item.length)
	bf.digitsToBuf(digits, bufRunes)
	if asciiCharset {
		for i := 0; i < item.length; i++ { bufBytes[i] = byte(bufRunes[i]) }
	}
	attempts := item.endIndex - item.startIndex

	if asciiCharset && batchDigester != nil && len(targetDigest) > 0 && item.length >= 16 {
		const batchSize = 64
		plainsBufs := make([][]byte, batchSize)
		for i := 0; i < batchSize; i++ { plainsBufs[i] = make([]byte, item.length) }
		for n := uint64(0); n < attempts; {
			remaining := int(attempts - n)
			if remaining > batchSize { remaining = batchSize }
			plains := plainsBufs[:remaining]
			for i := 0; i < remaining; i++ {
				copy(plains[i], bufBytes[:item.length])
				if i+1 < remaining {
					if asciiCharset {
						changed := bf.incrementDigitsInPlaceASCII(digits, bufBytes, item.length)
						if changed >= 0 { bufRunes[changed] = rune(bufBytes[changed]) }
					} else {
						changed := bf.incrementDigitsInPlace(digits)
						r := bf.charset[digits[changed]]
						bufRunes[changed] = r
					}
				}
			}
			sums, _ := batchDigester.DigestMany(plains, params)
			for i := 0; i < len(sums); i++ {
				(*localPending)++
				if len(sums[i]) == len(targetDigest) && constEq(sums[i], targetDigest) {
					return string(plains[i])
				}
				if *localPending >= progressInterval {
					globalCount := atomic.AddUint64(globalTried, *localPending)
					*localPending = 0
					if progressCb != nil {
						progressCb(globalCount, total, "", item.length)
					}
				}
			}
			n += uint64(len(plains))
			if n < attempts {
				if asciiCharset {
					changed := bf.incrementDigitsInPlaceASCII(digits, bufBytes, item.length)
					if changed >= 0 { bufRunes[changed] = rune(bufBytes[changed]) }
				} else {
					changed := bf.incrementDigitsInPlace(digits)
					r := bf.charset[digits[changed]]
					bufRunes[changed] = r
				}
			}
		}
		if *localPending > 0 {
			atomic.AddUint64(globalTried, *localPending)
			*localPending = 0
		}
		return ""
	}

	for n := uint64(0); n < attempts; n++ {
		var ok bool
		var candidateStr string

		if byteDigester != nil && len(targetDigest) > 0 && asciiCharset {
			sum, _ := byteDigester.DigestBytes(bufBytes[:item.length], params)
			ok = len(sum) == len(targetDigest) && constEq(sum, targetDigest)
			if ok {
				candidateStr = string(bufBytes[:item.length])
			}
		} else if runeDigester != nil {
			sum, _ := runeDigester.DigestRunes(bufRunes, item.length, params)
			if len(targetDigest) > 0 {
				ok = len(sum) == len(targetDigest) && constEq(sum, targetDigest)
			} else {
				candidateStr = string(bufRunes[:item.length])
				ok, _ = hasher.Compare(target, candidateStr, params)
			}
			if ok && candidateStr == "" { candidateStr = string(bufRunes[:item.length]) }
		} else {
			candidateStr = string(bufRunes[:item.length])
			ok, _ = hasher.Compare(target, candidateStr, params)
		}
		(*localPending)++

		if ok {
			return candidateStr
		}

		if n+1 < attempts {
			if asciiCharset {
				changed := bf.incrementDigitsInPlaceASCII(digits, bufBytes, item.length)
				if changed >= 0 {
					bufRunes[changed] = rune(bufBytes[changed])
				}
			} else {
				changed := bf.incrementDigitsInPlace(digits)
				r := bf.charset[digits[changed]]
				bufRunes[changed] = r
			}
		}

		for *localPending >= progressInterval {
			globalCount := atomic.AddUint64(globalTried, progressInterval)
			*localPending -= progressInterval
			if progressCb != nil {
				if candidateStr == "" {
					if asciiCharset {
						for i := 0; i < item.length; i++ { bufBytes[i] = byte(bufRunes[i]) }
						candidateStr = string(bufBytes[:item.length])
					} else {
						candidateStr = string(bufRunes[:item.length])
					}
				}
				progressCb(globalCount, total, candidateStr, item.length)
			}
		}
	}

	if *localPending > 0 {
		atomic.AddUint64(globalTried, *localPending)
		*localPending = 0
	}

	return ""
}

func (bf *ConcurrentBruteForcer) distributeWork(ctx context.Context, workChan chan<- workItem, total uint64) {
	defer close(workChan)
	
	for length := bf.minLen; length <= bf.maxLen; length++ {
		combinations := bf.calculateCombinationsForLength(length)
		
		batchSize := uint64(bf.batchSize)
		for start := uint64(0); start < combinations; start += batchSize {
			end := start + batchSize
			if end > combinations {
				end = combinations
			}
			
			item := workItem{
				startIndex: start,
				endIndex:   end,
				length:     length,
			}
			
			select {
			case workChan <- item:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (bf *ConcurrentBruteForcer) distributeWorkResumable(ctx context.Context, workChan chan<- workItem, total uint64) {
	defer close(workChan)
	
	globalIndex := uint64(0)
	
	for length := bf.minLen; length <= bf.maxLen; length++ {
		combinations := bf.calculateCombinationsForLength(length)
		
		batchSize := uint64(bf.batchSize)
		for start := uint64(0); start < combinations; start += batchSize {
			end := start + batchSize
			if end > combinations {
				end = combinations
			}
			
			batchStartGlobal := globalIndex + start
			batchEndGlobal := globalIndex + end
			
			// Skip if this batch is before our resume point
			if bf.startIdx > 0 && batchEndGlobal <= bf.startIdx {
				continue
			}
			
			// Adjust the batch if we're resuming from within it
			adjustedStart := start
			if bf.startIdx > 0 && batchStartGlobal < bf.startIdx && batchEndGlobal > bf.startIdx {
				adjustedStart = start + (bf.startIdx - batchStartGlobal)
			}
			
			item := workItem{
				startIndex: adjustedStart,
				endIndex:   end,
				length:     length,
			}
			
			select {
			case workChan <- item:
			case <-ctx.Done():
				return
			}
		}
		
		globalIndex += combinations
	}
}

func (bf *ConcurrentBruteForcer) calculateTotal() uint64 {
	total := uint64(0)
	for length := bf.minLen; length <= bf.maxLen; length++ {
		total += bf.calculateCombinationsForLength(length)
	}
	return total
}

func (bf *ConcurrentBruteForcer) calculateCombinationsForLength(length int) uint64 {
	combinations := uint64(1)
	charsetLen := uint64(len(bf.charset))
	for i := 0; i < length; i++ {
		combinations *= charsetLen
	}
	return combinations
}

func (bf *ConcurrentBruteForcer) indexToCombination(index uint64, length int, buf []rune) {
	charsetLen := uint64(len(bf.charset))
	
	for i := length - 1; i >= 0; i-- {
		buf[i] = bf.charset[index%charsetLen]
		index /= charsetLen
	}
}

func (bf *ConcurrentBruteForcer) indexToDigits(index uint64, length int) []int {
	charsetLen := uint64(len(bf.charset))
	digits := make([]int, length)
	for i := length - 1; i >= 0; i-- {
		digits[i] = int(index % charsetLen)
		index /= charsetLen
	}
	return digits
}

func (bf *ConcurrentBruteForcer) digitsToBuf(digits []int, buf []rune) {
	for i, d := range digits {
		buf[i] = bf.charset[d]
	}
}

func (bf *ConcurrentBruteForcer) incrementDigits(digits []int) {
	base := len(bf.charset)
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i] + 1
		if d < base {
			digits[i] = d
			return
		}
		digits[i] = 0
	}
}

func (bf *ConcurrentBruteForcer) incrementDigitsInPlace(digits []int) int {
	base := len(bf.charset)
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i] + 1
		if d < base {
			digits[i] = d
			return i
		}
		digits[i] = 0
	}
	return 0
}

func (bf *ConcurrentBruteForcer) isASCIICharset() bool {
	for _, r := range bf.charset {
		if r > 0x7F { return false }
	}
	return true
}

func constEq(a, b []byte) bool {
	if len(a) != len(b) { return false }
	var v byte
	for i := 0; i < len(a); i++ { v |= a[i] ^ b[i] }
	return v == 0
}

func (bf *ConcurrentBruteForcer) incrementDigitsInPlaceASCII(digits []int, bufBytes []byte, length int) int {
	base := len(bf.charset)
	for i := length - 1; i >= 0; i-- {
		d := digits[i] + 1
		if d < base {
			digits[i] = d
			bufBytes[i] = byte(bf.charset[d])
			return i
		}
		digits[i] = 0
		bufBytes[i] = byte(bf.charset[0])
	}
	return -1
}