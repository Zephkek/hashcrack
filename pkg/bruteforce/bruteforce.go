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

// go concurrency still sucks but better than doing this in.. god forbid.. python....
type ConcurrentBruteForcer struct {
	charset   []rune
	minLen    int
	maxLen    int
	workers   int
	batchSize int
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
		workers = runtime.NumCPU() * 2 // i like even numbers ok use x2 workers for a good distribution of I/O operations.. 
	}
	
	// batch sizes, we still use CPU so performance diff on this is pretty negligble 
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
	}
}

func (bf *ConcurrentBruteForcer) Crack(ctx context.Context, hasher hashes.Hasher, params hashes.Params, target string, progressCb ProgressCallback) (Result, error) {
	start := time.Now()
	var result Result
	var tried uint64
	
	total := bf.calculateTotal()

	// Fast-path: if the hasher can produce byte digests and the target is hex, decode once.
	var targetDigest []byte
	var byteDigester hashes.ByteDigester
	var runeDigester hashes.RuneDigester
	var batchDigester hashes.BatchByteDigester
	if bd, ok := hasher.(hashes.ByteDigester); ok {
		// Try to parse hex target; if it fails, we'll fall back to string Compare.
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


	workChan := make(chan workItem, bf.workers*4) // wasa3 lbuffer for more headroom 
	resultChan := make(chan string, 1)
	
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	var wg sync.WaitGroup
	for i := 0; i < bf.workers; i++ {
		wg.Add(1)
	go bf.worker(ctx, &wg, workChan, resultChan, hasher, params, target, targetDigest, byteDigester, runeDigester, batchDigester, &tried, total, progressCb)
	}
	
	go bf.distributeWork(ctx, workChan, total)
	
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
	
	result.Tried = atomic.LoadUint64(&tried)
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

	// Use rune buffer for general case; we also keep a byte buffer to avoid string allocations
	// for ASCII charsets where each rune fits in a single byte.
	bufRunes := make([]rune, bf.maxLen)
	bufBytes := make([]byte, bf.maxLen)
	asciiCharset := bf.isASCIICharset()
	localPending := uint64(0)
	progressInterval := uint64(2000)
	algo := strings.ToLower(hasher.Name())
	switch {
	case algo == "bcrypt":
		progressInterval = 50
	case algo == "scrypt":
		progressInterval = 100
	case strings.Contains(algo, "argon"):
		progressInterval = 100
	case total <= 100_000:
		progressInterval = 500  // More frequent for small tasks
	case total <= 5_000_000:
		progressInterval = 2_000
	default:
		progressInterval = 5_000  // Reduced for better stability
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
		// Initialize byte buffer once; subsequent increments keep it up-to-date
		for i := 0; i < item.length; i++ { bufBytes[i] = byte(bufRunes[i]) }
	}
	attempts := item.endIndex - item.startIndex

	// If we can batch (ASCII + targetDigest + batch digester present), do so for better SIMD utilization
	// Heuristic: batching helps mostly for larger inputs; for tiny (e.g., 8B MD5) it's slower.
	if asciiCharset && batchDigester != nil && len(targetDigest) > 0 && item.length >= 16 {
		// Choose a small batch size tuned for md5-simd lanes; 32 is a good default
		const batchSize = 32
		// Preallocate buffers to avoid per-candidate allocations
		plainsBufs := make([][]byte, batchSize)
		for i := 0; i < batchSize; i++ { plainsBufs[i] = make([]byte, item.length) }
		for n := uint64(0); n < attempts; {
			// Build batch
			remaining := int(attempts - n)
			if remaining > batchSize { remaining = batchSize }
			plains := plainsBufs[:remaining]
			// snapshot of candidates into reusable buffers since bufBytes mutates
			for i := 0; i < remaining; i++ {
				// ensure bufBytes is up to date for ASCII path
				if i == 0 {
					// first candidate already represented by current bufBytes
				}
				copy(plains[i], bufBytes[:item.length])
				if i+1 < remaining {
					// advance to next candidate
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
			// Compare
			for i := 0; i < len(sums); i++ {
				(*localPending)++
				if len(sums[i]) == len(targetDigest) && constEq(sums[i], targetDigest) {
					return string(plains[i])
				}
				if *localPending >= progressInterval {
					globalCount := atomic.AddUint64(globalTried, *localPending)
					*localPending = 0
					if progressCb != nil {
						progressCb(globalCount, total, string(plains[i]), item.length)
					}
				}
			}
			// After processing batch, advance one more candidate for next loop if any left
			n += uint64(len(plains))
			if n < attempts {
				// bufBytes already at last candidate of the batch; increment once to be at next start
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
			// If targetDigest available, compare bytes; else fallback to string compare
			if len(targetDigest) > 0 {
				ok = len(sum) == len(targetDigest) && constEq(sum, targetDigest)
			} else {
				// Fallback: compute text and compare via Hasher
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
				// Fast ASCII path: increment and update using a tight loop to reduce overhead
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
				// Avoid building candidate string unless necessary
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
		
		// Split work into batches
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

// converts an index to base-N digits where N=len(charset)
func (bf *ConcurrentBruteForcer) indexToDigits(index uint64, length int) []int {
	charsetLen := uint64(len(bf.charset))
	digits := make([]int, length)
	for i := length - 1; i >= 0; i-- {
		digits[i] = int(index % charsetLen)
		index /= charsetLen
	}
	return digits
}

// maps digit indices to runes in the buffer
func (bf *ConcurrentBruteForcer) digitsToBuf(digits []int, buf []rune) {
	for i, d := range digits {
		buf[i] = bf.charset[d]
	}
}

//adds one to the base-N number represented by digits
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

// incrementDigitsInPlace increments digits and returns the index that changed.
// If multiple carry positions occur, it returns the leftmost index that changed.
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

// isASCIICharset reports whether all characters in the charset are ASCII (<= 0x7F).
func (bf *ConcurrentBruteForcer) isASCIICharset() bool {
	for _, r := range bf.charset {
		if r > 0x7F { return false }
	}
	return true
}

// constEq does constant-time comparison of two equal-length byte slices.
func constEq(a, b []byte) bool {
	if len(a) != len(b) { return false }
	var v byte
	for i := 0; i < len(a); i++ { v |= a[i] ^ b[i] }
	return v == 0
}

// incrementDigitsInPlaceASCII increments digits and updates the ASCII byte buffer in-place.
// Returns the index that changed, or -1 if none.
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
