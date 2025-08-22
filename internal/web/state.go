package web

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type TaskState struct {
	TaskID           string            `json:"task_id"`
	Algo             string            `json:"algo"`
	Target           string            `json:"target"`
	Wordlist         string            `json:"wordlist,omitempty"`
	UseDefaultWordlist bool            `json:"use_default_wordlist"`
	Rules            []string          `json:"rules,omitempty"`
	Mask             string            `json:"mask,omitempty"`
	Salt             string            `json:"salt,omitempty"`
	Workers          int               `json:"workers"`
	Mode             string            `json:"mode"`
	BFMin            int               `json:"bf_min,omitempty"`
	BFMax            int               `json:"bf_max,omitempty"`
	BFChars          string            `json:"bf_chars,omitempty"`
	BcryptCost       int               `json:"bcrypt_cost,omitempty"`
	ScryptN          int               `json:"scrypt_n,omitempty"`
	ScryptR          int               `json:"scrypt_r,omitempty"`
	ScryptP          int               `json:"scrypt_p,omitempty"`
	ArgonTime        uint32            `json:"argon_time,omitempty"`
	ArgonMemKB       uint32            `json:"argon_mem_kb,omitempty"`
	ArgonPar         uint8             `json:"argon_par,omitempty"`
	
	Status           string            `json:"status"`
	TriedCount       uint64            `json:"tried_count"`
	TotalCount       uint64            `json:"total_count,omitempty"`
	
	WordlistLine     int64             `json:"wordlist_line,omitempty"`
	BruteforceIndex  uint64            `json:"bruteforce_index,omitempty"`
	MaskIndex        uint64            `json:"mask_index,omitempty"`
	CurrentLength    int               `json:"current_length,omitempty"`
	
	CreatedAt        time.Time         `json:"created_at"`
	LastCheckpoint   time.Time         `json:"last_checkpoint"`
	StartedAt        *time.Time        `json:"started_at,omitempty"`
	PausedAt         *time.Time        `json:"paused_at,omitempty"`
	TotalRuntime     time.Duration     `json:"total_runtime"`
	
	Found            bool              `json:"found"`
	Plaintext        string            `json:"plaintext,omitempty"`
	
	Detected         []string          `json:"detected,omitempty"`
}

type StateManager struct {
	mu          sync.RWMutex
	stateDir    string
	checkpoints map[string]*TaskState
}

func NewStateManager(stateDir string) (*StateManager, error) {
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}
	
	sm := &StateManager{
		stateDir:    stateDir,
		checkpoints: make(map[string]*TaskState),
	}
	
	if err := sm.LoadAllStates(); err != nil {
		log.Printf("Warning: failed to load existing states: %v", err)
	}
	
	return sm, nil
}

func (sm *StateManager) SaveState(state *TaskState) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	state.LastCheckpoint = time.Now()
	
	sm.checkpoints[state.TaskID] = state
	
	filename := filepath.Join(sm.stateDir, fmt.Sprintf("state_%s.json", state.TaskID))
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	
	// Write atomically by using a temp file
	tempFile := filename + ".tmp"
	if err := ioutil.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}
	
	if err := os.Rename(tempFile, filename); err != nil {
		os.Remove(tempFile) // Clean up
		return fmt.Errorf("failed to save state file: %w", err)
	}
	
	return nil
}

func (sm *StateManager) LoadState(taskID string) (*TaskState, error) {
	sm.mu.RLock()
	if state, ok := sm.checkpoints[taskID]; ok {
		sm.mu.RUnlock()
		return state, nil
	}
	sm.mu.RUnlock()
	
	filename := filepath.Join(sm.stateDir, fmt.Sprintf("state_%s.json", taskID))
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}
	
	var state TaskState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}
	
	sm.mu.Lock()
	sm.checkpoints[taskID] = &state
	sm.mu.Unlock()
	
	return &state, nil
}

// LoadAllStates loads all saved states from disk
func (sm *StateManager) LoadAllStates() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	files, err := ioutil.ReadDir(sm.stateDir)
	if err != nil {
		return fmt.Errorf("failed to read state directory: %w", err)
	}
	
	for _, file := range files {
		if file.IsDir() || !strings.HasPrefix(file.Name(), "state_") || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		
		filename := filepath.Join(sm.stateDir, file.Name())
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Printf("Failed to read state file %s: %v", filename, err)
			continue
		}
		
		var state TaskState
		if err := json.Unmarshal(data, &state); err != nil {
			log.Printf("Failed to unmarshal state file %s: %v", filename, err)
			continue
		}
		
		sm.checkpoints[state.TaskID] = &state
	}
	
	return nil
}

func (sm *StateManager) DeleteState(taskID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	delete(sm.checkpoints, taskID)
	
	filename := filepath.Join(sm.stateDir, fmt.Sprintf("state_%s.json", taskID))
	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete state file: %w", err)
	}
	
	return nil
}

func (sm *StateManager) GetAllStates() []*TaskState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	states := make([]*TaskState, 0, len(sm.checkpoints))
	for _, state := range sm.checkpoints {
		states = append(states, state)
	}
	
	return states
}

// GetResumableTasks returns tasks that can be resumed
func (sm *StateManager) GetResumableTasks() []*TaskState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	var resumable []*TaskState
	for _, state := range sm.checkpoints {
		if (state.Status == "running" || state.Status == "paused") && !state.Found {
			resumable = append(resumable, state)
		}
	}
	
	return resumable
}

func (sm *StateManager) UpdateProgress(taskID string, tried uint64, resumeData interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	state, ok := sm.checkpoints[taskID]
	if !ok {
		return fmt.Errorf("state not found for task %s", taskID)
	}
	
	state.TriedCount = tried
	state.LastCheckpoint = time.Now()
	
	switch data := resumeData.(type) {
	case int64:
		state.WordlistLine = data
	case uint64:
		if state.Mode == "bruteforce" {
			state.BruteforceIndex = data
		} else if state.Mode == "mask" {
			state.MaskIndex = data
		}
	case map[string]interface{}:
		if idx, ok := data["index"].(uint64); ok {
			if state.Mode == "bruteforce" {
				state.BruteforceIndex = idx
			} else if state.Mode == "mask" {
				state.MaskIndex = idx
			}
		}
		if length, ok := data["length"].(int); ok {
			state.CurrentLength = length
		}
		if line, ok := data["line"].(int64); ok {
			state.WordlistLine = line
		}
	}
	
	// Don't save to disk on every update, let the caller decide when to persist
	sm.checkpoints[taskID] = state
	
	return nil
}

// PauseTask marks a task as paused
func (sm *StateManager) PauseTask(taskID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	state, ok := sm.checkpoints[taskID]
	if !ok {
		return fmt.Errorf("state not found for task %s", taskID)
	}
	
	now := time.Now()
	state.Status = "paused"
	state.PausedAt = &now
	
	// Calculate total runtime
	if state.StartedAt != nil {
		state.TotalRuntime += now.Sub(*state.StartedAt)
	}
	
	return sm.SaveState(state)
}

// ResumeTask marks a task as resumed
func (sm *StateManager) ResumeTask(taskID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	state, ok := sm.checkpoints[taskID]
	if !ok {
		return fmt.Errorf("state not found for task %s", taskID)
	}
	
	now := time.Now()
	state.Status = "running"
	state.StartedAt = &now
	state.PausedAt = nil
	
	return sm.SaveState(state)
}

// CleanupOldStates removes states older than the specified duration
func (sm *StateManager) CleanupOldStates(maxAge time.Duration) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	cutoff := time.Now().Add(-maxAge)
	var toDelete []string
	
	for id, state := range sm.checkpoints {
		// Only clean up completed or error states
		if (state.Status == "done" || state.Status == "found" || state.Status == "error") &&
			state.LastCheckpoint.Before(cutoff) {
			toDelete = append(toDelete, id)
		}
	}
	
	for _, id := range toDelete {
		delete(sm.checkpoints, id)
		filename := filepath.Join(sm.stateDir, fmt.Sprintf("state_%s.json", id))
		if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
			log.Printf("Failed to delete old state file %s: %v", filename, err)
		}
	}
	
	return nil
}