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
