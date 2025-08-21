package web

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"edu/hashcrack/internal/cracker"
	"edu/hashcrack/internal/hashes"
	"edu/hashcrack/pkg/bruteforce"
	"edu/hashcrack/pkg/mask"
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
	
	// Internal fields for stable statistics calculation
	startTime         time.Time     `json:"-"`
	speedHistory      []speedSample `json:"-"`
	lastSpeedUpdate   time.Time     `json:"-"`
	avgWindow         time.Duration `json:"-"`
}

type speedSample struct {
	timestamp time.Time
	tried     uint64
	speed     float64
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

// updateStableSpeed calculates a more stable hash rate using moving average
func (p *TaskProgress) updateStableSpeed(tried uint64, now time.Time) {
	if p.avgWindow == 0 {
		p.avgWindow = 30 * time.Second // 30 second rolling window
	}
	
	if p.startTime.IsZero() {
		p.startTime = now
		p.lastSpeedUpdate = now
		return
	}
	
	// Calculate instantaneous speed if enough time has passed
	timeSinceLastUpdate := now.Sub(p.lastSpeedUpdate)
	if timeSinceLastUpdate >= 2*time.Second { // Update every 2 seconds minimum
		
		// Calculate overall average speed from start
		totalTime := now.Sub(p.startTime).Seconds()
		overallSpeed := float64(tried) / totalTime
		
		// Add sample to history
		sample := speedSample{
			timestamp: now,
			tried:     tried,
			speed:     overallSpeed,
		}
		p.speedHistory = append(p.speedHistory, sample)
		
		// Remove old samples outside the window
		cutoff := now.Add(-p.avgWindow)
		validSamples := p.speedHistory[:0]
		for _, s := range p.speedHistory {
			if s.timestamp.After(cutoff) {
				validSamples = append(validSamples, s)
			}
		}
		p.speedHistory = validSamples
		
		// Calculate weighted moving average
		if len(p.speedHistory) > 0 {
			totalWeight := 0.0
			weightedSum := 0.0
			
			for i, sample := range p.speedHistory {
				// Give more weight to recent samples
				weight := float64(i+1) / float64(len(p.speedHistory))
				totalWeight += weight
				weightedSum += sample.speed * weight
			}
			
			if totalWeight > 0 {
				p.AttemptsPerSecond = weightedSum / totalWeight
			}
		}
		
		p.lastSpeedUpdate = now
	}
}

// calculateStableETA provides a more stable ETA calculation
func (p *TaskProgress) calculateStableETA() {
	if p.Total > 0 && p.AttemptsPerSecond > 0 && p.Tried < p.Total {
		remaining := p.Total - p.Tried
		p.ETASeconds = float64(remaining) / p.AttemptsPerSecond
		
		// Cap unrealistic ETAs
		maxETA := 365 * 24 * 3600.0 // 1 year max
		if p.ETASeconds > maxETA {
			p.ETASeconds = maxETA
		}
	} else {
		p.ETASeconds = 0
	}
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

// preserve streaming support for sse
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
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
		// list uploaded files
		entries, err := os.ReadDir("uploads")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("Error reading uploads directory: %v", err)
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
		// handle file upload
		if err := r.ParseMultipartForm(maxUpload); err != nil {
			http.Error(w, "Invalid multipart form: "+err.Error(), 400)
			return
		}
		
		f, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "File field 'file' is required", 400)
			return
		}
		defer f.Close()
		
		// validate file size
		if hdr.Size > maxUpload {
			http.Error(w, fmt.Sprintf("File too large (max %dMB)", maxUpload/(1024*1024)), 413)
			return
		}
		
		if hdr.Size == 0 {
			http.Error(w, "Empty file not allowed", 400)
			return
		}
		
		// sanitize filename
		name := filepath.Base(hdr.Filename)
		if name == "" || name == "." || name == ".." {
			http.Error(w, "Invalid filename", 400)
			return
		}
		
		// validate file extension
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".txt" && ext != ".lst" {
			http.Error(w, "Only .txt and .lst files are supported", 400)
			return
		}
		
		// ensure uploads directory exists
		uploadsDir := "uploads"
		if err := os.MkdirAll(uploadsDir, 0755); err != nil {
			http.Error(w, "Failed to create uploads directory", 500)
			return
		}
		
		// create destination file with unique name if needed
		dstPath := filepath.Join(uploadsDir, name)
		counter := 1
		originalName := name
		for {
			if _, err := os.Stat(dstPath); os.IsNotExist(err) {
				break
			}
			// file exists, create unique name
			nameWithoutExt := strings.TrimSuffix(originalName, filepath.Ext(originalName))
			dstPath = filepath.Join(uploadsDir, fmt.Sprintf("%s_%d%s", nameWithoutExt, counter, filepath.Ext(originalName)))
			name = filepath.Base(dstPath)
			counter++
		}
		
		dst, err := os.Create(dstPath)
		if err != nil {
			http.Error(w, "Failed to create destination file", 500)
			return
		}
		defer dst.Close()
		
		// copy file content with size limit
		written, err := io.Copy(dst, io.LimitReader(f, maxUpload))
		if err != nil {
			os.Remove(dstPath) // clean up on error
			http.Error(w, "Failed to save file", 500)
			return
		}
		
		// verify content was written
		if written == 0 {
			os.Remove(dstPath) // clean up
			http.Error(w, "No content in uploaded file", 400)
			return
		}
		
		// validate file content (check if it's a valid wordlist)
		if err := validateWordlistFile(dstPath); err != nil {
			os.Remove(dstPath) // clean up invalid file
			http.Error(w, "Invalid wordlist file: "+err.Error(), 400)
			return
		}
		
		log.Printf("File uploaded: %s (%d bytes)", name, written)
		
		// return the path that the client should use
		response := map[string]any{
			"path":     "/uploads/" + name,
			"filename": name,
			"size":     written,
			"message":  "File uploaded successfully",
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		
	default:
		http.Error(w, "Method not allowed", 405)
	}
}

// validateWordlistFile checks if the uploaded file is a valid wordlist
func validateWordlistFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot open file: %v", err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineCount := 0
	emptyLines := 0
	maxLineLength := 0
	
	// Read first few lines to validate
	for scanner.Scan() && lineCount < 100 {
		line := strings.TrimSpace(scanner.Text())
		lineCount++
		
		if line == "" {
			emptyLines++
			continue
		}
		
		if len(line) > maxLineLength {
			maxLineLength = len(line)
		}
		
		// Check for obviously binary content
		for _, char := range line {
			if char < 32 && char != '\t' && char != '\n' && char != '\r' {
				return fmt.Errorf("file contains binary data (invalid character: %d)", char)
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}
	
	if lineCount == 0 {
		return fmt.Errorf("file is empty")
	}
	
	if emptyLines == lineCount {
		return fmt.Errorf("file contains only empty lines")
	}
	
	if maxLineLength > 1000 {
		return fmt.Errorf("file contains very long lines (max: %d chars), may not be a wordlist", maxLineLength)
	}
	
	return nil
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
		now := time.Now()
		p.LastUpdated = now
		p.startTime = now
		p.lastSpeedUpdate = now
		p.avgWindow = 30 * time.Second
		p.speedHistory = make([]speedSample, 0, 100) // Pre-allocate for efficiency
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
						
						// Use stable speed calculation
						p.updateStableSpeed(tried, now)
						
						// Calculate stable ETA
						p.calculateStableETA()
					}
					
					if percent, ok := kv["progress_percent"].(float64); ok {
						p.ProgressPercent = percent
					} else if p.Total > 0 {
						// Calculate progress percentage if not provided
						p.ProgressPercent = float64(p.Tried) / float64(p.Total) * 100
					}
					
					if candidate, ok := kv["candidate"].(string); ok {
						p.CurrentCandidate = candidate
					}
					if length, ok := kv["current_length"].(int); ok {
						p.CurrentLength = length
					}
					
					// Update system metrics less frequently to reduce noise
					var mem runtime.MemStats
					runtime.ReadMemStats(&mem)
					p.MemoryMB = float64(mem.Alloc) / 1024 / 1024
					p.CPUPercent = float64(runtime.NumGoroutine()) / float64(runtime.NumCPU()) * 10
				})
			}
		},
		ProgressEvery: 5000, // More frequent updates for stable statistics
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
				
				// Set total once and keep it stable
				if p.Total == 0 && total > 0 {
					p.Total = total
				}
				
				// Use stable speed calculation
				p.updateStableSpeed(tried, now)
				
				// Calculate stable progress and ETA
				if p.Total > 0 {
					p.ProgressPercent = float64(tried) / float64(p.Total) * 100
				}
				p.calculateStableETA()
				
				p.CurrentCandidate = candidate
				p.CurrentLength = currentLength
				
				// Update system metrics less frequently
				if now.Sub(p.LastUpdated) >= 5*time.Second {
					var mem runtime.MemStats
					runtime.ReadMemStats(&mem)
					p.MemoryMB = float64(mem.Alloc) / 1024 / 1024
				}
			})
			
			
			// Log event with stable progress
			progress := t.GetProgress()
			if progress != nil {
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{
					"event":             "progress",
					"tried":             tried,
					"total":             progress.Total,
					"progress_percent":  progress.ProgressPercent,
					"attempts_per_second": progress.AttemptsPerSecond,
					"eta_seconds":       progress.ETASeconds,
					"candidate":         candidate,
					"current_length":    currentLength,
				})
				eventMu.Unlock()
			}
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
		var wl string
		
		if t.UseDefaultWordlist {
			// using default wordlist
			if strings.TrimSpace(t.Wordlist) != "" {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": "Cannot use both default wordlist and custom wordlist. Choose one or the other."})
				eventMu.Unlock()
				return
			}
			
			wl = "testdata/rockyou-mini.txt"
			
			// verify default wordlist exists
			if _, err := os.Stat(wl); os.IsNotExist(err) {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Default wordlist not found: %s. Please check if the file exists.", wl)})
				eventMu.Unlock()
				return
			}
		} else {
			// using custom wordlist
			wl = strings.TrimSpace(t.Wordlist)
			if wl == "" {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": "Custom wordlist required. Please upload a wordlist file or select the default wordlist option."})
				eventMu.Unlock()
				return
			}
			
			// handle different path formats for uploaded files
			originalPath := wl
			
			// convert web path to filesystem path
			if strings.HasPrefix(wl, "/uploads/") {
				wl = strings.TrimPrefix(wl, "/")
			} else if !strings.Contains(wl, "/") && !strings.Contains(wl, "\\") {
				// just a filename, assume it's in uploads
				wl = filepath.Join("uploads", wl)
			}
			
			// verify custom wordlist exists and is readable
			fileInfo, err := os.Stat(wl)
			if os.IsNotExist(err) {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Wordlist file not found: %s (original path: %s). Please ensure the file was uploaded correctly.", wl, originalPath)})
				eventMu.Unlock()
				return
			} else if err != nil {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Cannot access wordlist file: %s. Error: %v", wl, err)})
				eventMu.Unlock()
				return
			}
			
			// check if file is not empty
			if fileInfo.Size() == 0 {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Wordlist file is empty: %s", wl)})
				eventMu.Unlock()
				return
			}
		}
		
		// final validation - try to open and read first line
		file, err := os.Open(wl)
		if err != nil {
			t.Status = "error"
			eventMu.Lock()
			t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Failed to open wordlist file: %s. Error: %v", wl, err)})
			eventMu.Unlock()
			return
		}
		
		scanner := bufio.NewScanner(file)
		hasContent := false
		lineCount := 0
		for scanner.Scan() && lineCount < 5 {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				hasContent = true
				break
			}
			lineCount++
		}
		file.Close()
		
		if !hasContent {
			t.Status = "error"
			eventMu.Lock()
			t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Wordlist file appears to be empty or contains no valid entries: %s", wl)})
			eventMu.Unlock()
			return
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
		} else {
			p.ProgressPercent = 100.0 // Task completed
		}
		p.ETASeconds = 0 // Task is complete
		
		// Final speed calculation
		if !p.startTime.IsZero() {
			totalTime := time.Since(p.startTime).Seconds()
			if totalTime > 0 {
				p.AttemptsPerSecond = float64(res.Tried) / totalTime
			}
		}
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
