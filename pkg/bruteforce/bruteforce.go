package bruteforce

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"strings"

	"edu/hashcrack/internal/hashes"
)

// go concurrency still sucks but better than doing this in.. god forbid.. python....
type ConcurrentBruteForcer struct {
	charset   []rune
	charsetB  []byte
	asciiOnly bool
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
	
	rs := []rune(charset)
	ascii := true
	bs := make([]byte, len(rs))
	for i, r := range rs {
		if r > 0x7F { ascii = false }
		if r <= 0xFF {
			bs[i] = byte(r)
		} else {
			// placeholder
			bs[i] = 0
		}
	}
	return &ConcurrentBruteForcer{
		charset:   rs,
		charsetB:  bs,
		asciiOnly: ascii,
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
	

	workChan := make(chan workItem, bf.workers*4) // wasa3 lbuffer for more headroom 
	resultChan := make(chan string, 1)
	
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	var wg sync.WaitGroup
	for i := 0; i < bf.workers; i++ {
		wg.Add(1)
		go bf.worker(ctx, &wg, workChan, resultChan, hasher, params, target, &tried, total, progressCb)
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
	tried *uint64,
	total uint64,
	progressCb ProgressCallback,
) {
	defer wg.Done()
	
	buf := make([]rune, bf.maxLen) // ReUsE
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
			
			found := bf.processWorkItem(item, buf, hasher, params, target, &localPending, progressInterval, tried, total, progressCb)
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
	buf []rune,
	hasher hashes.Hasher,
	params hashes.Params,
	target string,
	localPending *uint64,
	progressInterval uint64,
	globalTried *uint64,
	total uint64,
	progressCb ProgressCallback,
) string {
	digits := bf.indexToDigits(item.startIndex, item.length)
	bf.digitsToBuf(digits, buf)
	attempts := item.endIndex - item.startIndex
	// Prepare fast-path interfaces if available
	bc, _ := hasher.(hashes.ByteComparer)
	bbc, _ := hasher.(hashes.BatchByteComparer)
	// small batch buffer for batch hashing, tuned for SIMD servers (16 lanes)
	const lane = 16
	batch := make([][]byte, 0, lane)
	// candidate byte buffer reused when asciiOnly
	cand := make([]byte, item.length)

	for n := uint64(0); n < attempts; n++ {
		if bf.asciiOnly && (bbc != nil || bc != nil) {
			// Fast ASCII path: map digits to bytes directly with no string alloc
			for i := 0; i < item.length; i++ {
				cand[i] = bf.charsetB[digits[i]]
			}
			if bbc != nil {
				// batch
				b := make([]byte, item.length)
				copy(b, cand[:item.length])
				batch = append(batch, b)
				(*localPending)++
				if len(batch) == lane || n+1 == attempts {
					if idx, _ := bbc.CompareBatchHex(target, batch, params); idx >= 0 {
						return string(batch[idx])
					}
					batch = batch[:0]
				}
			} else { // bc only
				ok, _ := bc.CompareBytes(target, cand[:item.length], params)
				(*localPending)++
				if ok {
					return string(cand[:item.length])
				}
			}
		} else {
			// Fallback path using strings
			candidate := string(buf[:item.length])
			if bbc != nil {
				batch = append(batch, []byte(candidate))
				(*localPending)++
				if len(batch) == lane || n+1 == attempts {
					if idx, _ := bbc.CompareBatchHex(target, batch, params); idx >= 0 {
						return string(batch[idx])
					}
					batch = batch[:0]
				}
			} else {
				ok, _ := hasher.Compare(target, candidate, params)
				(*localPending)++
				if ok { return candidate }
			}
		}

		if n+1 < attempts {
			bf.incDigitsAndBuf(digits, buf)
		}

		for *localPending >= progressInterval {
			globalCount := atomic.AddUint64(globalTried, progressInterval)
			*localPending -= progressInterval
			if progressCb != nil {
				// provide a recent candidate for visibility
				recent := string(buf[:item.length])
				progressCb(globalCount, total, recent, item.length)
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

// increment digits and update buf at the changed positions to avoid full remap
func (bf *ConcurrentBruteForcer) incDigitsAndBuf(digits []int, buf []rune) {
	base := len(bf.charset)
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i] + 1
		if d < base {
			digits[i] = d
			buf[i] = bf.charset[d]
			return
		}
		digits[i] = 0
		buf[i] = bf.charset[0]
	}
}
