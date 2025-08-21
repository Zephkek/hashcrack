package web

import (
	"context"
	"encoding/json"
	"fmt"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"edu/hashcrack/internal/cracker"
	"edu/hashcrack/internal/hashes"
	"edu/hashcrack/pkg/mask"
	"edu/hashcrack/pkg/bruteforce"
	"runtime"
	"strconv"
)

type Task struct {
	ID        string            `json:"id"`
	Algo      string            `json:"algo"`
	Target    string            `json:"target"`
	Wordlist  string            `json:"wordlist"`
	UseDefaultWordlist bool     `json:"use_default_wordlist"`
	Rules     []string          `json:"rules"`
	Mask      string            `json:"mask"`
	Salt      string            `json:"salt"`
	Workers   int               `json:"workers"`
	Mode      string            `json:"mode"`
	BFMin     int               `json:"bf_min"`
	BFMax     int               `json:"bf_max"`
	BFChars   string            `json:"bf_chars"`
	BcryptCost int             `json:"bcrypt_cost"`
	ScryptN    int             `json:"scrypt_n"`
	ScryptR    int             `json:"scrypt_r"`
	ScryptP    int             `json:"scrypt_p"`
	ArgonTime  uint32          `json:"argon_time"`
	ArgonMemKB uint32          `json:"argon_mem_kb"`
	ArgonPar   uint8           `json:"argon_par"`
	Status    string            `json:"status"`
	Result    *cracker.Result   `json:"result,omitempty"`
	Events    []map[string]any  `json:"events,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	StartedAt *time.Time        `json:"started_at,omitempty"`
	Detected  []string          `json:"detected,omitempty"`
	Progress  *TaskProgress     `json:"progress,omitempty"`
	
	// mutex for updates
	progressMu sync.RWMutex     `json:"-"`
}

type TaskProgress struct {
	Tried             uint64    `json:"tried"`
	Total             uint64    `json:"total,omitempty"`
	ProgressPercent   float64   `json:"progress_percent"`
	AttemptsPerSecond float64   `json:"attempts_per_second"`
	ETASeconds        float64   `json:"eta_seconds,omitempty"`
	CurrentCandidate  string    `json:"current_candidate,omitempty"`
	CurrentLength     int       `json:"current_length,omitempty"`
	CPUPercent        float64   `json:"cpu_percent"`
	MemoryMB          float64   `json:"memory_mb"`
	LastUpdated       time.Time `json:"last_updated"`
}

// update progress safely
func (t *Task) UpdateProgress(update func(*TaskProgress)) {
	t.progressMu.Lock()
	defer t.progressMu.Unlock()
	
	if t.Progress == nil {
		t.Progress = &TaskProgress{
			LastUpdated: time.Now(),
		}
	}
	
	update(t.Progress)
	t.Progress.LastUpdated = time.Now()
}

// get progress (returns copy)
func (t *Task) GetProgress() *TaskProgress {
	t.progressMu.RLock()
	defer t.progressMu.RUnlock()
	
	if t.Progress == nil {
		return nil
	}
	
	// copy to avoid races
	p := *t.Progress
	return &p
}

type Manager struct {
	mu       sync.RWMutex
	seq      int
	tasks    map[string]*Task
	contexts map[string]context.CancelFunc // cancellation stuff
}

func NewManager() *Manager {
	return &Manager{
		tasks:    map[string]*Task{},
		contexts: map[string]context.CancelFunc{},
	}
}

func (m *Manager) nextID() string {
	m.seq++
	// short ID: 4char base36 time + 2char seq, uppercase
	nowMs := time.Now().UnixNano() / 1e6
	tsPart := strconv.FormatInt(nowMs%(36*36*36*36), 36) // 4 chars max
	seqPart := strconv.FormatInt(int64(m.seq%(36*36)), 36) // 2 chars
	id := strings.ToUpper(padLeft(tsPart, 4) + "-" + padLeft(seqPart, 2))
	return id
}

func padLeft(s string, n int) string {
	if len(s) >= n { return s }
	return strings.Repeat("0", n-len(s)) + s
}

func (m *Manager) Add(t *Task) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextID()
	t.ID = id
	m.tasks[id] = t
	return id
}

func (m *Manager) Get(id string) (*Task, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tasks[id]
	return t, ok
}

func (m *Manager) List() []*Task {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		out = append(out, t)
	}
	// sort newest first
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// http server
type Server struct {
	m *Manager
}

func NewServer(m *Manager) *Server {
	return &Server{m: m}
}

// wrapper for logging
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// log requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
	})
}

// cors for dev
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	
	// api routes
	mux.HandleFunc("/api/tasks", s.handleTasks)
	mux.HandleFunc("/api/tasks/", s.handleTaskWithActions)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/uploads", s.handleUploads)
	mux.HandleFunc("/api/algorithms", s.handleAlgorithms)
	mux.HandleFunc("/api/detect", s.handleDetect)
	
	// static stuff
	staticDir := "web/static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		log.Printf("Warning: static dir %s missing", staticDir)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
	
	// uploads
	uploadsDir := "uploads"
	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(uploadsDir, 0755); err != nil {
			log.Printf("Warning: cant create uploads: %v", err)
		}
	}
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir(uploadsDir))))
	
	// main
	mux.HandleFunc("/", s.handleIndex)
	
	// wrap with middleware
	return corsMiddleware(loggingMiddleware(mux))
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// root only
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	// change to whatever index location you like for this container this is the location
	possiblePaths := []string{
		"web/template/index.html",
	}
	
	var indexPath string
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			indexPath = path
			break
		}
	}
	
	if indexPath == "" {
		log.Printf("Error: cant find index.html in: %v", possiblePaths)
		http.Error(w, "index.html not found", 500)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, indexPath)
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.m.List())
	case http.MethodPost:
		var req struct {
			Algo string `json:"algo"`
			Target string `json:"target"`
			Wordlist string `json:"wordlist"`
			UseDefaultWordlist bool `json:"use_default_wordlist"`
			Rules []string `json:"rules"`
			Mask string `json:"mask"`
			Salt string `json:"salt"`
			Workers int `json:"workers"`
			Mode string `json:"mode"`
			BFMin int `json:"bf_min"`
			BFMax int `json:"bf_max"`
			BFChars string `json:"bf_chars"`
			BcryptCost int `json:"bcrypt_cost"`
			ScryptN int `json:"scrypt_n"`
			ScryptR int `json:"scrypt_r"`
			ScryptP int `json:"scrypt_p"`
			ArgonTime uint32 `json:"argon_time"`
			ArgonMemKB uint32 `json:"argon_mem_kb"`
			ArgonPar uint8 `json:"argon_par"`
		}
		
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		
		algo := strings.TrimSpace(strings.ToLower(req.Algo))
		detected := []string(nil)
        
		// compute suggestions but need explicit algo
		{
			raw := hashes.Detect(req.Target)
			if len(raw) > 0 {
				reg := map[string]struct{}{}
				for _, n := range hashes.List() { reg[n] = struct{}{} }
				for _, n := range raw { if _, ok := reg[n]; ok { detected = append(detected, n) } }
			}
		}
		if algo == "" || algo == "auto" {
			http.Error(w, "algorithm must be selected explicitly (auto-detect shows suggestions only)", 400)
			return
		}
		
		h, err := hashes.Get(algo)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		
		t := &Task{
			Algo: algo,
			Target: req.Target,
			Wordlist: req.Wordlist,
			UseDefaultWordlist: req.UseDefaultWordlist,
			Rules: req.Rules,
			Mask: req.Mask,
			Salt: req.Salt,
			Workers: req.Workers,
			Mode: req.Mode,
			BFMin: req.BFMin,
			BFMax: req.BFMax,
			BFChars: req.BFChars,
			BcryptCost: req.BcryptCost,
			ScryptN: req.ScryptN,
			ScryptR: req.ScryptR,
			ScryptP: req.ScryptP,
			ArgonTime: req.ArgonTime,
			ArgonMemKB: req.ArgonMemKB,
			ArgonPar: req.ArgonPar,
			Status: "queued",
			CreatedAt: time.Now(),
			Detected: detected,
		}
		
		id := s.m.Add(t)
		go s.runTask(id, t, h)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(t)
		
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) handleTaskWithActions(w http.ResponseWriter, r *http.Request) {
	// parse url
	path := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	if path == "" || path == "/" {
		http.NotFound(w, r)
		return
	}
	
	parts := strings.Split(path, "/")
	taskID := parts[0]
	
	// check for action
	var action string
	if len(parts) > 1 {
		action = parts[1]
	}
	
	switch r.Method {
	case http.MethodGet:
		// get task
		t, ok := s.m.Get(taskID)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(t)
		
	case http.MethodDelete:
		// delete
		s.m.mu.Lock()
		defer s.m.mu.Unlock()
		
		if _, exists := s.m.tasks[taskID]; !exists {
			http.NotFound(w, r)
			return
		}
		
		// stop if running
		if cancel, ok := s.m.contexts[taskID]; ok {
			cancel()
			delete(s.m.contexts, taskID)
		}
		
		delete(s.m.tasks, taskID)
		
		w.WriteHeader(http.StatusNoContent)
		
	case http.MethodPost:
		// actions
		if action == "stop" {
			s.m.mu.Lock()
			defer s.m.mu.Unlock()
			
			t, exists := s.m.tasks[taskID]
			if !exists {
				http.NotFound(w, r)
				return
			}
			
			// cancel context
			if cancel, ok := s.m.contexts[taskID]; ok {
				cancel()
				delete(s.m.contexts, taskID)
			}
			
			// update stat
			if t.Status == "running" {
				t.Status = "stopped"
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
		} else {
			http.Error(w, "Unknown action", 400)
		}
		
	default:
		http.Error(w, "Method not allowed", 405)
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			data, _ := json.Marshal(s.m.List())
			fmt.Fprintf(w, "event: tasks\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	// runtime stats + cpu/mem
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	
	// calc running task stats
	tasks := s.m.List()
	runningTasks := 0
	totalAttempts := uint64(0)
	totalSpeed := float64(0)
	
	for _, task := range tasks {
		if task.Status == "running" {
			runningTasks++
			if progress := task.GetProgress(); progress != nil {
				totalAttempts += progress.Tried
				totalSpeed += progress.AttemptsPerSecond
			}
		}
	}
	
	// build response
	out := map[string]any{
		"timestamp": time.Now().Unix(),
		"system": map[string]any{
			"goroutines":     runtime.NumGoroutine(),
			"num_cpu":        runtime.NumCPU(),
			"alloc_bytes":    mem.Alloc,
			"alloc_mb":       float64(mem.Alloc) / 1024 / 1024,
			"sys_bytes":      mem.Sys,
			"sys_mb":         float64(mem.Sys) / 1024 / 1024,
			"heap_inuse":     mem.HeapInuse,
			"heap_inuse_mb":  float64(mem.HeapInuse) / 1024 / 1024,
			"heap_objects":   mem.HeapObjects,
			"gc_cycles":      mem.NumGC,
			"next_gc_mb":     float64(mem.NextGC) / 1024 / 1024,
		},
		"tasks": map[string]any{
			"total":               len(tasks),
			"running":             runningTasks,
			"total_attempts":      totalAttempts,
			"total_speed_per_sec": totalSpeed,
		},
		"status": "ok",
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	
	if err := json.NewEncoder(w).Encode(out); err != nil {
		log.Printf("Error encoding stats: %v", err)
		http.Error(w, "Internal server error", 500)
		return
	}
}

// list algos
func (s *Server) handleAlgorithms(w http.ResponseWriter, r *http.Request) {
	list := hashes.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"algorithms": list})
}

// detect algos for target
func (s *Server) handleDetect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	cands := hashes.Detect(target)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"candidates": cands})
}

const maxUpload = 10 << 20 // 10mb

func (s *Server) handleUploads(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// list
		entries, err := os.ReadDir("uploads")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(w, err.Error(), 500)
			return
		}
		var files []string
		for _, e := range entries {
			if !e.IsDir() {
				files = append(files, "/uploads/"+e.Name())
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"files": files})
		
	case http.MethodPost:
		if err := r.ParseMultipartForm(maxUpload); err != nil {
			http.Error(w, "invalid form", 400)
			return
		}
		
		f, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", 400)
			return
		}
		defer f.Close()
		
		if hdr.Size > maxUpload {
			http.Error(w, "file too large", 413)
			return
		}
		
		name := filepath.Base(hdr.Filename)
		// only txt/lst
		if !strings.HasSuffix(strings.ToLower(name), ".txt") && !strings.HasSuffix(strings.ToLower(name), ".lst") {
			http.Error(w, "unsupported file type", 400)
			return
		}
		
		_ = os.MkdirAll("uploads", 0o755)
		dstPath := filepath.Join("uploads", name)
		dst, err := os.Create(dstPath)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer dst.Close()
		
		if _, err := io.Copy(dst, io.LimitReader(f, maxUpload)); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"path": "/uploads/" + name})
		
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) runTask(id string, t *Task, h hashes.Hasher) {
	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	
	// Store cancel function
	s.m.mu.Lock()
	s.m.contexts[id] = cancel
	s.m.mu.Unlock()
	
	// Clean up on exit
	defer func() {
		s.m.mu.Lock()
		delete(s.m.contexts, id)
		s.m.mu.Unlock()
		cancel()
	}()
	
	// Check for early cancellation
	s.m.mu.RLock()
	if t.Status == "cancelled" || t.Status == "stopped" {
		s.m.mu.RUnlock()
		return
	}
	s.m.mu.RUnlock()
	
	eventMu := sync.Mutex{}
	var startTime time.Time
	var lastProgressTime time.Time
	var lastTriedCount uint64
	
	// Clamp workers: minimum 1, max NumCPU
	w := t.Workers
	if w < 1 {
		w = 1
	}
	if w > runtime.NumCPU() {
		w = runtime.NumCPU()
	}
	
	// Initialize progress tracking
	t.UpdateProgress(func(p *TaskProgress) {
		p.LastUpdated = time.Now()
	})
	
	c := cracker.New(cracker.Options{
		Workers: w,
		Event: func(event string, kv map[string]any) {
			eventMu.Lock()
			t.Events = append(t.Events, kv)
			eventMu.Unlock()
			
			// Update progress based on event type
			switch event {
			case "start":
				startTime = time.Now()
				lastProgressTime = startTime
				t.StartedAt = &startTime
				
				t.UpdateProgress(func(p *TaskProgress) {
					if total, ok := kv["total_combinations"].(uint64); ok {
						p.Total = total
					}
				})
				
			case "progress":
				now := time.Now()
				
				t.UpdateProgress(func(p *TaskProgress) {
					if tried, ok := kv["tried"].(uint64); ok {
						p.Tried = tried
						
						// Calculate attempts per second
						if !lastProgressTime.IsZero() {
							timeDiff := now.Sub(lastProgressTime).Seconds()
							triedDiff := tried - lastTriedCount
							if timeDiff > 0 {
								p.AttemptsPerSecond = float64(triedDiff) / timeDiff
							}
						}
						
						// Calculate ETA
						if p.Total > 0 && p.AttemptsPerSecond > 0 {
							remaining := p.Total - tried
							p.ETASeconds = float64(remaining) / p.AttemptsPerSecond
						}
					}
					
					if percent, ok := kv["progress_percent"].(float64); ok {
						p.ProgressPercent = percent
					}
					if candidate, ok := kv["candidate"].(string); ok {
						p.CurrentCandidate = candidate
					}
					if length, ok := kv["current_length"].(int); ok {
						p.CurrentLength = length
					}
					
					// Update system metrics
					var mem runtime.MemStats
					runtime.ReadMemStats(&mem)
					p.MemoryMB = float64(mem.Alloc) / 1024 / 1024
					p.CPUPercent = float64(runtime.NumGoroutine()) / float64(runtime.NumCPU()) * 10
				})
				
				lastProgressTime = now
				lastTriedCount, _ = kv["tried"].(uint64)
			}
		},
		Transform: buildTransform(t.Rules),
	})
	defer c.Close()
	
	params := hashes.Params{
		Salt:             []byte(t.Salt),
		BcryptCost:       t.BcryptCost,
		ScryptN:          t.ScryptN,
		ScryptR:          t.ScryptR,
		ScryptP:          t.ScryptP,
		ArgonTime:        t.ArgonTime,
		ArgonMemoryKB:    t.ArgonMemKB,
		ArgonParallelism: t.ArgonPar,
	}
	
	t.Status = "running"
	var res cracker.Result
	var err error
	
	mode := strings.ToLower(strings.TrimSpace(t.Mode))
	if mode == "mask" && t.Mask != "" {
		gen, gerr := mask.NewGenerator(t.Mask)
		if gerr != nil {
			t.Status = "error"
			eventMu.Lock()
			t.Events = append(t.Events, map[string]any{"error": gerr.Error()})
			eventMu.Unlock()
			return
		}
		res, err = gen.Crack(ctx, c, h, params, t.Target)
		
	} else if mode == "bruteforce" {
		// High-performance bruteforce using optimized concurrent implementation
		bfChars := t.BFChars
		if bfChars == "" {
			bfChars = "abcdefghijklmnopqrstuvwxyz0123456789"
		}
		if t.BFMin <= 0 {
			t.BFMin = 1
		}
		if t.BFMax < t.BFMin {
			t.BFMax = t.BFMin
		}
		
		// Use the new high-performance brute forcer
		bf := bruteforce.New(bfChars, t.BFMin, t.BFMax, w)
		
		bfResult, bfErr := bf.Crack(ctx, h, params, t.Target, func(tried, total uint64, candidate string, currentLength int) {
			// Convert to cracker.Result format and report progress
			now := time.Now()
			
			t.UpdateProgress(func(p *TaskProgress) {
				p.Tried = tried
				// Set total once; keep it stable so ETA doesn't fluctuate
				if p.Total == 0 && total > 0 {
					p.Total = total
				}
				
				// Calculate speed and ETA
				if !lastProgressTime.IsZero() {
					timeDiff := now.Sub(lastProgressTime).Seconds()
					triedDiff := tried - lastTriedCount
					if timeDiff > 0 {
						p.AttemptsPerSecond = float64(triedDiff) / timeDiff
					}
				}
				
				if p.Total > 0 {
					p.ProgressPercent = float64(tried) / float64(p.Total) * 100
					if p.AttemptsPerSecond > 0 {
						remaining := p.Total - tried
						p.ETASeconds = float64(remaining) / p.AttemptsPerSecond
					}
				}
				
				p.CurrentCandidate = candidate
				p.CurrentLength = currentLength
				
				// Update system metrics
				var mem runtime.MemStats
				runtime.ReadMemStats(&mem)
				p.MemoryMB = float64(mem.Alloc) / 1024 / 1024
			})
			
			lastProgressTime = now
			lastTriedCount = tried
			
			// Log event
			eventMu.Lock()
			t.Events = append(t.Events, map[string]any{
				"event":           "progress",
				"tried":           tried,
				"total":           total,
				"progress_percent": float64(tried) / float64(total) * 100,
				"candidate":       candidate,
				"current_length":  currentLength,
			})
			eventMu.Unlock()
		})
		
		if bfErr != nil {
			err = bfErr
		} else {
			// Convert bruteforce result to cracker result
			res = cracker.Result{
				Found:     bfResult.Found,
				Plaintext: bfResult.Plaintext,
				Tried:     bfResult.Tried,
				Duration:  bfResult.Duration,
			}
		}
		
	} else {
		// wordlist mode
		wl := strings.TrimSpace(t.Wordlist)

		// FIX: Handle default wordlist properly
		if t.UseDefaultWordlist {
			if wl != "" {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": "Choose either default wordlist or custom upload, not both."})
				eventMu.Unlock()
				return
			}
			wl = "testdata/rockyou-mini.txt"

			// FIX: Check if default wordlist exists
			if _, err := os.Stat(wl); os.IsNotExist(err) {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Default wordlist not found: %s", wl)})
				eventMu.Unlock()
				return
			}
		} else {
			// FIX: Handle custom wordlist paths
			if wl == "" {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": "Wordlist required (default or custom)."})
				eventMu.Unlock()
				return
			}

			// FIX: Proper path resolution for uploaded files
			if strings.HasPrefix(wl, "/uploads/") {
				wl = strings.TrimPrefix(wl, "/")
			}

			// FIX: Verify custom wordlist exists
			if _, err := os.Stat(wl); os.IsNotExist(err) {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Wordlist file not found: %s", wl)})
				eventMu.Unlock()
				return
			}
		}

		res, err = c.CrackWordlist(ctx, h, params, t.Target, wl)
	}
	
	if err != nil {
		t.Status = "error"
		eventMu.Lock()
		t.Events = append(t.Events, map[string]any{"error": err.Error()})
		eventMu.Unlock()
		return
	}
	
	t.Result = &res
	if res.Found {
		t.Status = "found"
	} else {
		t.Status = "done"
	}
	
	// Final progress update
	t.UpdateProgress(func(p *TaskProgress) {
		p.Tried = res.Tried
		if p.Total > 0 {
			p.ProgressPercent = float64(res.Tried) / float64(p.Total) * 100
		}
		p.ETASeconds = 0 // Task is complete
	})
}


func (s *Server) Start(addr string) error {
	log.Printf("Starting HashCrack web server on %s", addr)
	return http.ListenAndServe(addr, s.routes())
}

// buildTransform - simple rules for wordlist mods
// rules:
//   +u  uppercase
//   +l  lowercase
//   +c  capitalize
//   +d1 append 1 digit
//   +d2 append 2 digits
func buildTransform(rules []string) func(string) []string {
	if len(rules) == 0 {
		return nil
	}
	return func(s string) []string {
		out := []string{s}
		for _, r := range rules {
			switch r {
			case "+u":
				out = append(out, strings.ToUpper(s))
			case "+l":
				out = append(out, strings.ToLower(s))
			case "+c":
				if len(s) > 0 {
					out = append(out, strings.ToUpper(s[:1])+s[1:])
				}
			case "+d1":
				for i := 0; i < 10; i++ {
					out = append(out, s+string('0'+i))
				}
			case "+d2":
				for i := 0; i < 100; i++ {
					out = append(out, s+fmt.Sprintf("%02d", i))
				}
			}
		}
		return out
	}
}
