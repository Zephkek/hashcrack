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
	
	IsPaused         bool          `json:"is_paused"`
	LastCheckpoint   time.Time     `json:"last_checkpoint,omitempty"`
	WordlistLine     int64         `json:"wordlist_line,omitempty"`
	BruteforceIndex  uint64        `json:"bruteforce_index,omitempty"`
	MaskIndex        uint64        `json:"mask_index,omitempty"`
	CurrentLength    int           `json:"current_length,omitempty"`
	TotalRuntime     time.Duration `json:"total_runtime,omitempty"`
	
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
	lastSampleTried   uint64        `json:"-"`
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
		p.avgWindow = 30 * time.Second
	}
	
	if p.startTime.IsZero() {
		p.startTime = now
		p.lastSpeedUpdate = now
		p.lastSampleTried = tried
		return
	}
	
	timeSinceLastUpdate := now.Sub(p.lastSpeedUpdate)
	if timeSinceLastUpdate >= 1*time.Second {
		// Use delta-based speed to avoid spikes after resume
		var deltaTried uint64
		if tried >= p.lastSampleTried {
			deltaTried = tried - p.lastSampleTried
		} else {
			// If counter reset unexpectedly, treat as absolute
			deltaTried = tried
		}
		secs := timeSinceLastUpdate.Seconds()
		if secs > 0 {
			sampleSpeed := float64(deltaTried) / secs
			sample := speedSample{
				timestamp: now,
				tried:     tried,
				speed:     sampleSpeed,
			}
			p.speedHistory = append(p.speedHistory, sample)
		}
		
		cutoff := now.Add(-p.avgWindow)
		validSamples := p.speedHistory[:0]
		for _, s := range p.speedHistory {
			if s.timestamp.After(cutoff) {
				validSamples = append(validSamples, s)
			}
		}
		p.speedHistory = validSamples
		
		if len(p.speedHistory) > 0 {
			totalWeight := 0.0
			weightedSum := 0.0
			
			for i, sample := range p.speedHistory {
				weight := float64(i+1) / float64(len(p.speedHistory))
				totalWeight += weight
				weightedSum += sample.speed * weight
			}
			
			if totalWeight > 0 {
				p.AttemptsPerSecond = weightedSum / totalWeight
			}
		}
		p.lastSampleTried = tried
		p.lastSpeedUpdate = now
	}
}

// calculateStableETA provides a more stable ETA calculation
func (p *TaskProgress) calculateStableETA() {
	if p.Total > 0 && p.AttemptsPerSecond > 0 && p.Tried < p.Total {
		remaining := p.Total - p.Tried
		p.ETASeconds = float64(remaining) / p.AttemptsPerSecond
		
		maxETA := 365 * 24 * 3600.0
		if p.ETASeconds > maxETA {
			p.ETASeconds = maxETA
		}
	} else {
		p.ETASeconds = 0
	}
}

type Manager struct {
	mu           sync.RWMutex
	seq          int
	tasks        map[string]*Task
	contexts     map[string]context.CancelFunc
	stateManager *StateManager
	
	// Checkpoint settings
	checkpointInterval time.Duration
	lastCheckpoint     map[string]time.Time
}

// TaskDTO is a lightweight view for UI responses (excludes heavy/internal fields like Events)
type TaskDTO struct {
	ID                 string           `json:"id"`
	Algo               string           `json:"algo"`
	Mode               string           `json:"mode"`
	Mask               string           `json:"mask,omitempty"`
	Wordlist           string           `json:"wordlist,omitempty"`
	UseDefaultWordlist bool             `json:"use_default_wordlist"`
	BFMin              int              `json:"bf_min,omitempty"`
	BFMax              int              `json:"bf_max,omitempty"`
	Detected           []string         `json:"detected,omitempty"`
	Status             string           `json:"status"`
	IsPaused           bool             `json:"is_paused"`
	LastCheckpoint     time.Time        `json:"last_checkpoint,omitempty"`
	Result             *cracker.Result  `json:"result,omitempty"`
	Progress           *TaskProgress    `json:"progress,omitempty"`
}

func taskToDTO(t *Task) *TaskDTO {
	if t == nil { return nil }
	dto := &TaskDTO{
		ID:                 t.ID,
		Algo:               t.Algo,
		Mode:               t.Mode,
		Mask:               t.Mask,
		Wordlist:           t.Wordlist,
		UseDefaultWordlist: t.UseDefaultWordlist,
		BFMin:              t.BFMin,
		BFMax:              t.BFMax,
		Detected:           t.Detected,
		Status:             t.Status,
		IsPaused:           t.IsPaused,
		LastCheckpoint:     t.LastCheckpoint,
		Result:             t.Result,
		Progress:           t.GetProgress(),
	}
	return dto
}

func tasksToDTOs(tasks []*Task) []*TaskDTO {
	out := make([]*TaskDTO, 0, len(tasks))
	for _, t := range tasks { out = append(out, taskToDTO(t)) }
	return out
}

// Shutdown gracefully pauses running tasks and persists their state
func (m *Manager) Shutdown(ctx context.Context) {
	// Collect task IDs to avoid holding lock during cancellations
	m.mu.RLock()
	ids := make([]string, 0, len(m.tasks))
	for id := range m.tasks {
		ids = append(ids, id)
	}
	m.mu.RUnlock()

	deadline := time.Now().Add(5 * time.Second)
	for _, id := range ids {
		m.mu.Lock()
		t, ok := m.tasks[id]
		if ok && t.Status == "running" {
			t.Status = "paused"
			t.IsPaused = true
			// Persist immediately
			m.saveTaskState(t)
			if cancel, exists := m.contexts[id]; exists {
				cancel()
				delete(m.contexts, id)
			}
		}
		m.mu.Unlock()

		if time.Now().After(deadline) {
			break
		}
	}
}

func NewManager() *Manager {
	// Initialize state manager (configurable directory)
	stateDir := os.Getenv("HASHCRACK_STATE_DIR")
	if strings.TrimSpace(stateDir) == "" {
		stateDir = "states"
	}
	stateManager, err := NewStateManager(stateDir)
	if err != nil {
		log.Printf("Warning: Failed to initialize state manager: %v", err)
	}
	
	m := &Manager{
		tasks:              map[string]*Task{},
		contexts:           map[string]context.CancelFunc{},
		stateManager:       stateManager,
		checkpointInterval: 30 * time.Second, // Save state every 30 seconds
		lastCheckpoint:     map[string]time.Time{},
	}
	
	// Restore any saved tasks
	if stateManager != nil {
		m.restoreSavedTasks()
	}
	
	// Start cleanup routine
	go m.cleanupRoutine()
	
	log.Printf("State directory: %s", stateDir)
	return m
}

func (m *Manager) restoreSavedTasks() {
	resumable := m.stateManager.GetResumableTasks()
	for _, state := range resumable {
		// Convert state to task
		task := &Task{
			ID:                 state.TaskID,
			Algo:               state.Algo,
			Target:             state.Target,
			Wordlist:           state.Wordlist,
			UseDefaultWordlist: state.UseDefaultWordlist,
			Rules:              state.Rules,
			Mask:               state.Mask,
			Salt:               state.Salt,
			Workers:            state.Workers,
			Mode:               state.Mode,
			BFMin:              state.BFMin,
			BFMax:              state.BFMax,
			BFChars:            state.BFChars,
			BcryptCost:         state.BcryptCost,
			ScryptN:            state.ScryptN,
			ScryptR:            state.ScryptR,
			ScryptP:            state.ScryptP,
			ArgonTime:          state.ArgonTime,
			ArgonMemKB:         state.ArgonMemKB,
			ArgonPar:           state.ArgonPar,
			Status:             "paused",
			CreatedAt:          state.CreatedAt,
			StartedAt:          state.StartedAt,
			Detected:           state.Detected,
			IsPaused:           true,
			LastCheckpoint:     state.LastCheckpoint,
			WordlistLine:       state.WordlistLine,
			BruteforceIndex:    state.BruteforceIndex,
			MaskIndex:          state.MaskIndex,
			CurrentLength:      state.CurrentLength,  // Added this
			TotalRuntime:       state.TotalRuntime,
		}
		
		// Set progress
		task.UpdateProgress(func(p *TaskProgress) {
			p.Tried = state.TriedCount
			p.Total = state.TotalCount
			if p.Total > 0 {
				p.ProgressPercent = float64(p.Tried) / float64(p.Total) * 100
			}
		})
		
		m.tasks[task.ID] = task
		log.Printf("Restored task %s from saved state (tried: %d)", task.ID, state.TriedCount)
	}
}

func (m *Manager) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		if m.stateManager != nil {
			// Clean up states older than 7 days
			if err := m.stateManager.CleanupOldStates(7 * 24 * time.Hour); err != nil {
				log.Printf("Failed to cleanup old states: %v", err)
			}
		}
	}
}

func (m *Manager) saveTaskState(task *Task) {
	if m.stateManager == nil {
		return
	}
	
	progress := task.GetProgress()
	
	state := &TaskState{
		TaskID:             task.ID,
		Algo:               task.Algo,
		Target:             task.Target,
		Wordlist:           task.Wordlist,
		UseDefaultWordlist: task.UseDefaultWordlist,
		Rules:              task.Rules,
		Mask:               task.Mask,
		Salt:               task.Salt,
		Workers:            task.Workers,
		Mode:               task.Mode,
		BFMin:              task.BFMin,
		BFMax:              task.BFMax,
		BFChars:            task.BFChars,
		BcryptCost:         task.BcryptCost,
		ScryptN:            task.ScryptN,
		ScryptR:            task.ScryptR,
		ScryptP:            task.ScryptP,
		ArgonTime:          task.ArgonTime,
		ArgonMemKB:         task.ArgonMemKB,
		ArgonPar:           task.ArgonPar,
		Status:             task.Status,
		CreatedAt:          task.CreatedAt,
		StartedAt:          task.StartedAt,
		Detected:           task.Detected,
		WordlistLine:       task.WordlistLine,
		BruteforceIndex:    task.BruteforceIndex,
		MaskIndex:          task.MaskIndex,
		CurrentLength:      task.CurrentLength,  // Added this
		TotalRuntime:       task.TotalRuntime,
	}
	
	if progress != nil {
		state.TriedCount = progress.Tried
		state.TotalCount = progress.Total
	}
	
	if task.Result != nil {
		state.Found = task.Result.Found
		state.Plaintext = task.Result.Plaintext
	}
	
	if err := m.stateManager.SaveState(state); err != nil {
		log.Printf("Failed to save state for task %s: %v", task.ID, err)
	}
}

func (m *Manager) nextID() string {
	m.seq++
	nowMs := time.Now().UnixNano() / 1e6
	tsPart := strconv.FormatInt(nowMs%(36*36*36*36), 36)
	seqPart := strconv.FormatInt(int64(m.seq%(36*36)), 36)
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
	m.saveTaskState(t)
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// PauseTask pauses a running task
func (m *Manager) PauseTask(taskID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	task, ok := m.tasks[taskID]
	if !ok {
		return fmt.Errorf("task not found")
	}
	
	if task.Status != "running" {
		// Idempotent: if already paused, pretend success
		if task.Status == "paused" { return nil }
		return fmt.Errorf("task is not running")
	}

	// Mark paused first to avoid race with runTask finalization
	task.Status = "paused"
	task.IsPaused = true

	// Save state before cancelling so runTask can detect pause
	m.saveTaskState(task)

	// Cancel the context to stop the task
	if cancel, ok := m.contexts[taskID]; ok {
		cancel()
		delete(m.contexts, taskID)
	}
	
	return nil
}

// ResumeTask resumes a paused task
func (m *Manager) ResumeTask(taskID string) error {
	m.mu.Lock()
	task, ok := m.tasks[taskID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("task not found")
	}
	
	if task.Status != "paused" {
		m.mu.Unlock()
		return fmt.Errorf("task is not paused")
	}
	
	// Get the hasher
	h, err := hashes.Get(task.Algo)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	
	task.Status = "running"
	task.IsPaused = false
	m.mu.Unlock()
	
	// Resume the task
	go m.runTask(taskID, task, h)
	
	return nil
}

// Server struct
type Server struct {
	m *Manager
}

func NewServer(m *Manager) *Server {
	return &Server{m: m}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapped.statusCode, time.Since(start))
	})
}

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
	
	mux.HandleFunc("/api/tasks", s.handleTasks)
	mux.HandleFunc("/api/tasks/", s.handleTaskWithActions)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/tasks/stream", s.handleTasksStream)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/uploads", s.handleUploads)
	mux.HandleFunc("/api/algorithms", s.handleAlgorithms)
	mux.HandleFunc("/api/detect", s.handleDetect)
	
	staticDir := "web/static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		log.Printf("Warning: static dir %s missing", staticDir)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
	
	uploadsDir := "uploads"
	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(uploadsDir, 0755); err != nil {
			log.Printf("Warning: cant create uploads: %v", err)
		}
	}
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir(uploadsDir))))
	
	mux.HandleFunc("/", s.handleIndex)
	
	return corsMiddleware(loggingMiddleware(mux))
}
// Server-Sent Events for tasks list to smooth UI updates
func (s *Server) handleTasksStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	// Send initial payload
	data, _ := json.Marshal(tasksToDTOs(s.m.List()))
	fmt.Fprintf(w, "event: tasks\ndata: %s\n\n", data)
	flusher.Flush()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			data, _ := json.Marshal(tasksToDTOs(s.m.List()))
			fmt.Fprintf(w, "event: tasks\ndata: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			// send comment heartbeat to keep proxies from closing the connection
			fmt.Fprintf(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	possiblePaths := []string{
		"web/templates/index.html",
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
	json.NewEncoder(w).Encode(tasksToDTOs(s.m.List()))
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
		go s.m.runTask(id, t, h)
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(t)
		
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (s *Server) handleTaskWithActions(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	if path == "" || path == "/" {
		http.NotFound(w, r)
		return
	}
	
	parts := strings.Split(path, "/")
	taskID := parts[0]
	
	var action string
	if len(parts) > 1 {
		action = parts[1]
	}
	
	switch r.Method {
	case http.MethodGet:
		t, ok := s.m.Get(taskID)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(taskToDTO(t))
		
	case http.MethodDelete:
		s.m.mu.Lock()
		defer s.m.mu.Unlock()
		
		if _, exists := s.m.tasks[taskID]; !exists {
			http.NotFound(w, r)
			return
		}
		
		if cancel, ok := s.m.contexts[taskID]; ok {
			cancel()
			delete(s.m.contexts, taskID)
		}
		
		// Delete saved state
		if s.m.stateManager != nil {
			s.m.stateManager.DeleteState(taskID)
		}
		
		delete(s.m.tasks, taskID)
		
		w.WriteHeader(http.StatusNoContent)
		
	case http.MethodPost:
		if action == "stop" {
			s.m.mu.Lock()
			defer s.m.mu.Unlock()
			
			t, exists := s.m.tasks[taskID]
			if !exists {
				http.NotFound(w, r)
				return
			}
			
			// Mark task stopped immediately to avoid race flicker
			t.Status = "stopped"
			t.IsPaused = false
			
			// Cancel any running context
			if cancel, ok := s.m.contexts[taskID]; ok {
				cancel()
				delete(s.m.contexts, taskID)
			}
			
			// Remove saved resume state since task is explicitly stopped
			if s.m.stateManager != nil {
				s.m.stateManager.DeleteState(taskID)
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
			
		} else if action == "pause" {
			if err := s.m.PauseTask(taskID); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "paused"})
			
		} else if action == "resume" {
			if err := s.m.ResumeTask(taskID); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "resumed"})
			
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
	w.Header().Set("X-Accel-Buffering", "no")
	
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
    
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			data, _ := json.Marshal(tasksToDTOs(s.m.List()))
			fmt.Fprintf(w, "event: tasks\ndata: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	
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

func (s *Server) handleAlgorithms(w http.ResponseWriter, r *http.Request) {
	list := hashes.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"algorithms": list})
}

func (s *Server) handleDetect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	cands := hashes.Detect(target)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"candidates": cands})
}

const maxUpload = 10 << 20

func (s *Server) handleUploads(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
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
		
		if hdr.Size > maxUpload {
			http.Error(w, fmt.Sprintf("File too large (max %dMB)", maxUpload/(1024*1024)), 413)
			return
		}
		
		if hdr.Size == 0 {
			http.Error(w, "Empty file not allowed", 400)
			return
		}
		
		name := filepath.Base(hdr.Filename)
		if name == "" || name == "." || name == ".." {
			http.Error(w, "Invalid filename", 400)
			return
		}
		
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".txt" && ext != ".lst" {
			http.Error(w, "Only .txt and .lst files are supported", 400)
			return
		}
		
		uploadsDir := "uploads"
		if err := os.MkdirAll(uploadsDir, 0755); err != nil {
			http.Error(w, "Failed to create uploads directory", 500)
			return
		}
		
		dstPath := filepath.Join(uploadsDir, name)
		counter := 1
		originalName := name
		for {
			if _, err := os.Stat(dstPath); os.IsNotExist(err) {
				break
			}
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
		
		written, err := io.Copy(dst, io.LimitReader(f, maxUpload))
		if err != nil {
			os.Remove(dstPath)
			http.Error(w, "Failed to save file", 500)
			return
		}
		
		if written == 0 {
			os.Remove(dstPath)
			http.Error(w, "No content in uploaded file", 400)
			return
		}
		
		if err := validateWordlistFile(dstPath); err != nil {
			os.Remove(dstPath)
			http.Error(w, "Invalid wordlist file: "+err.Error(), 400)
			return
		}
		
		log.Printf("File uploaded: %s (%d bytes)", name, written)
		
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

func (m *Manager) runTask(id string, t *Task, h hashes.Hasher) {
	ctx, cancel := context.WithCancel(context.Background())
	
	m.mu.Lock()
	m.contexts[id] = cancel
	m.mu.Unlock()
	
	defer func() {
		m.mu.Lock()
		delete(m.contexts, id)
		m.mu.Unlock()
		cancel()
	}()
	
	m.mu.RLock()
	if t.Status == "cancelled" || t.Status == "stopped" || t.Status == "paused" {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()
	
	eventMu := sync.Mutex{}
	var startTime time.Time
	
	w := t.Workers
	if w < 1 {
		w = 1
	}
	if w > runtime.NumCPU() {
		w = runtime.NumCPU()
	}
	
	t.UpdateProgress(func(p *TaskProgress) {
		now := time.Now()
		p.LastUpdated = now
		p.startTime = now
		p.lastSpeedUpdate = now
		p.avgWindow = 30 * time.Second
		p.speedHistory = make([]speedSample, 0, 100)
	// Initialize speed baseline to current tried to avoid spikes on resume
	p.lastSampleTried = p.Tried
	})
	
	// Track checkpoint timing
	lastCheckpointTime := time.Now()
	checkpointMutex := sync.Mutex{}
	
	c := cracker.New(cracker.Options{
		Workers: w,
		Event: func(event string, kv map[string]any) {
			eventMu.Lock()
			t.Events = append(t.Events, kv)
			// Cap events to last 1000 to avoid unbounded growth
			if len(t.Events) > 1000 {
				trim := len(t.Events) - 1000
				copy(t.Events[0:], t.Events[trim:])
				t.Events = t.Events[:1000]
			}
			eventMu.Unlock()
			
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
						p.updateStableSpeed(tried, now)
						p.calculateStableETA()
					}
					
					if percent, ok := kv["progress_percent"].(float64); ok {
						p.ProgressPercent = percent
					} else if p.Total > 0 {
						p.ProgressPercent = float64(p.Tried) / float64(p.Total) * 100
					}
					
					if candidate, ok := kv["candidate"].(string); ok {
						p.CurrentCandidate = candidate
					}
					if length, ok := kv["current_length"].(int); ok {
						p.CurrentLength = length
					}
					
					// Throttle memory sampling to once every ~3 seconds to reduce overhead
					if now.Sub(p.LastUpdated) >= 3*time.Second {
						var mem runtime.MemStats
						runtime.ReadMemStats(&mem)
						p.MemoryMB = float64(mem.Alloc) / 1024 / 1024
						p.CPUPercent = float64(runtime.NumGoroutine()) / float64(runtime.NumCPU()) * 10
					}
				})
				
				// Save checkpoint periodically
				checkpointMutex.Lock()
				if time.Since(lastCheckpointTime) >= m.checkpointInterval {
					m.saveTaskState(t)
					lastCheckpointTime = time.Now()
				}
				checkpointMutex.Unlock()
			}
	},
	ProgressEvery: 3000,
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
	
	// If a stop was issued just before starting, do not run
	m.mu.RLock()
	if t.Status == "stopped" {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()
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
		
		if t.MaskIndex > 0 {
			gen.SetStartIndex(t.MaskIndex)
		}
		
		res, err = gen.Crack(ctx, c, h, params, t.Target)
		
	} else if mode == "bruteforce" {
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
		
		bf := bruteforce.New(bfChars, t.BFMin, t.BFMax, w)
		
		if t.BruteforceIndex > 0 {
			bf.SetStartIndex(t.BruteforceIndex)
		}
		
		bfResult, bfErr := bf.Crack(ctx, h, params, t.Target, func(tried, total uint64, candidate string, currentLength int) {
			now := time.Now()
			
			t.UpdateProgress(func(p *TaskProgress) {
				p.Tried = tried
				
				if p.Total == 0 && total > 0 {
					p.Total = total
				}
				
				p.updateStableSpeed(tried, now)
				
				if p.Total > 0 {
					p.ProgressPercent = float64(tried) / float64(p.Total) * 100
				}
				p.calculateStableETA()
				
				p.CurrentCandidate = candidate
				p.CurrentLength = currentLength
				
				if now.Sub(p.LastUpdated) >= 5*time.Second {
					var mem runtime.MemStats
					runtime.ReadMemStats(&mem)
					p.MemoryMB = float64(mem.Alloc) / 1024 / 1024
				}
			})
			
			// Update checkpoint data
			t.BruteforceIndex = tried
			t.CurrentLength = currentLength
			
			// Save checkpoint periodically
			checkpointMutex.Lock()
			if time.Since(lastCheckpointTime) >= m.checkpointInterval {
				m.saveTaskState(t)
				lastCheckpointTime = time.Now()
			}
			checkpointMutex.Unlock()
			
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
			res = cracker.Result{
				Found:     bfResult.Found,
				Plaintext: bfResult.Plaintext,
				Tried:     bfResult.Tried,
				Duration:  bfResult.Duration,
			}
		}
		
	} else {
		// Wordlist mode with resume support
		var wl string
		
		if t.UseDefaultWordlist {
			if strings.TrimSpace(t.Wordlist) != "" {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": "Cannot use both default wordlist and custom wordlist. Choose one or the other."})
				eventMu.Unlock()
				return
			}
			
			wl = "testdata/rockyou-mini.txt"
			
			if _, err := os.Stat(wl); os.IsNotExist(err) {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Default wordlist not found: %s. Please check if the file exists.", wl)})
				eventMu.Unlock()
				return
			}
		} else {
			wl = strings.TrimSpace(t.Wordlist)
			if wl == "" {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": "Custom wordlist required. Please upload a wordlist file or select the default wordlist option."})
				eventMu.Unlock()
				return
			}
			
			originalPath := wl
			
			if strings.HasPrefix(wl, "/uploads/") {
				wl = strings.TrimPrefix(wl, "/")
			} else if !strings.Contains(wl, "/") && !strings.Contains(wl, "\\") {
				wl = filepath.Join("uploads", wl)
			}
			
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
			
			if fileInfo.Size() == 0 {
				t.Status = "error"
				eventMu.Lock()
				t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Wordlist file is empty: %s", wl)})
				eventMu.Unlock()
				return
			}
		}
		
		// Quick sanity check for non-empty wordlist by stat only; avoid double scanning
		if info, err := os.Stat(wl); err != nil || info.Size() == 0 {
			t.Status = "error"
			eventMu.Lock()
			t.Events = append(t.Events, map[string]any{"error": fmt.Sprintf("Wordlist file appears to be empty or cannot be accessed: %s (err=%v)", wl, err)})
			eventMu.Unlock()
			return
		}
		
		// Create a resumable cracker with checkpoint support
		resumableOpts := cracker.ResumableOptions{
			StartLine:      t.WordlistLine,
			CheckpointFunc: func(line int64) {
				t.WordlistLine = line
				
				// Save checkpoint periodically
				checkpointMutex.Lock()
				if time.Since(lastCheckpointTime) >= m.checkpointInterval {
					m.saveTaskState(t)
					lastCheckpointTime = time.Now()
				}
				checkpointMutex.Unlock()
			},
		}
		
		res, err = c.CrackWordlistResumable(ctx, h, params, t.Target, wl, resumableOpts)
	}
	
	if err != nil {
		// If the task was paused or stopped via context cancel, preserve that status
		m.mu.RLock()
		status := t.Status
		m.mu.RUnlock()
		if status == "paused" || status == "stopped" || status == "cancelled" {
			// Persist current paused/stopped state and exit quietly
			m.saveTaskState(t)
			return
		}
		t.Status = "error"
		eventMu.Lock()
		t.Events = append(t.Events, map[string]any{"error": err.Error()})
		eventMu.Unlock()
		// Save error state
		m.saveTaskState(t)
		return
	}
	
	// If we were paused/stopped while cracking, don't overwrite status with done
	m.mu.RLock()
	finalStatus := t.Status
	m.mu.RUnlock()
	if finalStatus == "paused" || finalStatus == "stopped" || finalStatus == "cancelled" {
		// Persist the latest progress and exit without changing status
		m.saveTaskState(t)
		return
	}

	t.Result = &res
	if res.Found {
		t.Status = "found"
	} else {
		t.Status = "done"
	}
	
	t.UpdateProgress(func(p *TaskProgress) {
		p.Tried = res.Tried
		if p.Total > 0 {
			p.ProgressPercent = float64(res.Tried) / float64(p.Total) * 100
		} else {
			p.ProgressPercent = 100.0
		}
		p.ETASeconds = 0
		
		if !p.startTime.IsZero() {
			totalTime := time.Since(p.startTime).Seconds()
			if totalTime > 0 {
				p.AttemptsPerSecond = float64(res.Tried) / totalTime
			}
		}
	})
	
	// Save final state
	m.saveTaskState(t)
	
	// Clean up saved state only when completed (not paused)
	if t.Status == "found" || t.Status == "done" {
		if m.stateManager != nil {
			m.stateManager.DeleteState(t.ID)
		}
	}
}

func (s *Server) Start(addr string) error {
	log.Printf("Starting HashCrack web server on %s", addr)
	log.Printf("State persistence enabled - tasks will resume after restart")
	return http.ListenAndServe(addr, s.routes())
}

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