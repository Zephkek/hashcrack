package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"edu/hashcrack/internal/cracker"
	"edu/hashcrack/internal/hashes"
	"edu/hashcrack/pkg/mask"
	"edu/hashcrack/internal/web"
)

// parseSalt decodes salt from hex string to bytes, falling back to literal string if hex decode fails
func parseSalt(salt string) []byte {
	if salt == "" {
		return nil
	}
	// Try to decode as hex first
	if decoded, err := hex.DecodeString(salt); err == nil {
		return decoded
	}
	// Fall back to literal string
	return []byte(salt)
}

var (
	workers  int
	timeout  time.Duration
	config   string
	logPath  string
	verbose  bool
)

var rootCmd = &cobra.Command{
	Use:   "hashcrack",
	Short: "HashCrack - A fast, concurrent hash-cracking toolkit",
	Long: `HashCrack is a high-performance hash cracking tool designed for 
cybersecurity education and research purposes. Supports 400+ hash algorithms and 6 attack modes.`, 
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if config != "" {
			viper.SetConfigFile(config)
			if err := viper.ReadInConfig(); err != nil {
				log.Printf("Warning: Could not read config file: %v", err)
			}
		}
		
		if workers > 0 {
			viper.Set("workers", workers)
		}
		if logPath != "" {
			viper.Set("log", logPath)
		}
	},
}

var crackCmd = &cobra.Command{
	Use:   "crack",
	Short: "Crack a single hash",
	Long:  `Crack a single hash using wordlist, mask, or brute force attack.`,
	RunE:  runCrack,
}

var batchCmd = &cobra.Command{
	Use:   "batch",
	Short: "Crack multiple hashes from a file",
	Long:  `Process a batch file containing multiple hashes in the format: algorithm:hash`,
	RunE:  runBatch,
}

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the web UI server",
	Long:  `Start the HashCrack web interface for interactive hash cracking.`,
	RunE:  runWeb,
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List supported algorithms",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Supported algorithms:")
		for _, algo := range hashes.List() {
			fmt.Printf("  - %s\n", algo)
		}
	},
}

var combinationCmd = &cobra.Command{
	Use:   "combination",
	Short: "Combination attack (concatenate words from two wordlists)",
	RunE:  runCombination,
}

var hybridCmd = &cobra.Command{
	Use:   "hybrid",
	Short: "Hybrid attack (wordlist + mask or mask + wordlist)",
	RunE:  runHybrid,
}

var associationCmd = &cobra.Command{
	Use:   "association",
	Short: "Association attack (use username, filename, hint to generate candidates)",
	RunE:  runAssociation,
}

func init() {
	rootCmd.PersistentFlags().IntVarP(&workers, "workers", "t", 0, "Number of worker threads (default: CPU cores)")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 0, "Timeout for cracking attempts")
	rootCmd.PersistentFlags().StringVar(&config, "config", "", "Config file path")
	rootCmd.PersistentFlags().StringVar(&logPath, "log", "", "Log file path for events")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	crackCmd.Flags().StringP("algorithm", "a", "auto", "Hash algorithm (auto-detect by default)")
	crackCmd.Flags().StringP("hash", "H", "", "Target hash to crack (required)")
	crackCmd.Flags().StringP("wordlist", "w", "", "Wordlist file path")
	crackCmd.Flags().StringP("mask", "m", "", "Mask pattern (e.g., ?l?l?l?d?d)")
	crackCmd.Flags().String("charset", "abcdefghijklmnopqrstuvwxyz0123456789", "Character set for brute force")
	crackCmd.Flags().Int("min-length", 1, "Minimum password length for brute force")
	crackCmd.Flags().Int("max-length", 6, "Maximum password length for brute force")
	crackCmd.Flags().String("salt", "", "Salt value (if applicable)")
	crackCmd.Flags().String("rules", "", "Comma-separated transformation rules (+u,+l,+c,+d1,+d2)")
	
	// Algorithm-specific parameters
	crackCmd.Flags().Int("pbkdf2-iterations", 10000, "PBKDF2 iteration count")
	crackCmd.Flags().Int("bcrypt-cost", 12, "Bcrypt cost parameter")
	crackCmd.Flags().Int("scrypt-n", 32768, "Scrypt N parameter")
	crackCmd.Flags().Int("scrypt-r", 8, "Scrypt R parameter") 
	crackCmd.Flags().Int("scrypt-p", 1, "Scrypt P parameter")
	crackCmd.Flags().Uint32("argon-time", 1, "Argon2 time parameter")
	crackCmd.Flags().Uint32("argon-memory", 65536, "Argon2 memory in KB")
	crackCmd.Flags().Uint8("argon-parallelism", 4, "Argon2 parallelism parameter")
	
	crackCmd.MarkFlagRequired("hash")

	batchCmd.Flags().StringP("file", "f", "", "Batch file path (required)")
	batchCmd.Flags().StringP("wordlist", "w", "", "Wordlist file path")
	batchCmd.Flags().String("output", "", "Output file for results")
	batchCmd.MarkFlagRequired("file")

	webCmd.Flags().String("addr", ":8080", "Server address (host:port)")
	webCmd.Flags().String("static", "web/static", "Static files directory")
	webCmd.Flags().String("templates", "web/templates", "Template files directory")

	combinationCmd.Flags().StringP("algorithm", "a", "auto", "Hash algorithm")
	combinationCmd.Flags().StringP("hash", "H", "", "Target hash (required)")
	combinationCmd.Flags().String("wordlist1", "", "First wordlist file (required)")
	combinationCmd.Flags().String("wordlist2", "", "Second wordlist file (required)")
	combinationCmd.Flags().String("separator", "", "Separator between words (default: none)")
	combinationCmd.Flags().StringP("salt", "s", "", "Salt value")
	
	// Algorithm-specific parameters for combination
	combinationCmd.Flags().Int("pbkdf2-iterations", 10000, "PBKDF2 iteration count")
	combinationCmd.Flags().Int("bcrypt-cost", 12, "Bcrypt cost parameter")
	combinationCmd.Flags().Int("scrypt-n", 32768, "Scrypt N parameter")
	combinationCmd.Flags().Int("scrypt-r", 8, "Scrypt R parameter") 
	combinationCmd.Flags().Int("scrypt-p", 1, "Scrypt P parameter")
	combinationCmd.Flags().Uint32("argon-time", 1, "Argon2 time parameter")
	combinationCmd.Flags().Uint32("argon-memory", 65536, "Argon2 memory in KB")
	combinationCmd.Flags().Uint8("argon-parallelism", 4, "Argon2 parallelism parameter")
	
	combinationCmd.MarkFlagRequired("hash")
	combinationCmd.MarkFlagRequired("wordlist1")
	combinationCmd.MarkFlagRequired("wordlist2")

	hybridCmd.Flags().StringP("algorithm", "a", "auto", "Hash algorithm")
	hybridCmd.Flags().StringP("hash", "H", "", "Target hash (required)")
	hybridCmd.Flags().StringP("wordlist", "w", "", "Wordlist file (required)")
	hybridCmd.Flags().StringP("mask", "m", "", "Mask pattern (required)")
	hybridCmd.Flags().Bool("prefix", false, "Use mask as prefix (default: suffix)")
	hybridCmd.Flags().StringP("salt", "s", "", "Salt value")
	
	// Algorithm-specific parameters for hybrid
	hybridCmd.Flags().Int("pbkdf2-iterations", 10000, "PBKDF2 iteration count")
	hybridCmd.Flags().Int("bcrypt-cost", 12, "Bcrypt cost parameter")
	hybridCmd.Flags().Int("scrypt-n", 32768, "Scrypt N parameter")
	hybridCmd.Flags().Int("scrypt-r", 8, "Scrypt R parameter") 
	hybridCmd.Flags().Int("scrypt-p", 1, "Scrypt P parameter")
	hybridCmd.Flags().Uint32("argon-time", 1, "Argon2 time parameter")
	hybridCmd.Flags().Uint32("argon-memory", 65536, "Argon2 memory in KB")
	hybridCmd.Flags().Uint8("argon-parallelism", 4, "Argon2 parallelism parameter")
	
	hybridCmd.MarkFlagRequired("hash")
	hybridCmd.MarkFlagRequired("wordlist")
	hybridCmd.MarkFlagRequired("mask")

	associationCmd.Flags().StringP("algorithm", "a", "auto", "Hash algorithm")
	associationCmd.Flags().StringP("hash", "H", "", "Target hash (required)")
	associationCmd.Flags().String("username", "", "Username for association")
	associationCmd.Flags().String("hint", "", "Password hint")
	associationCmd.Flags().String("filename", "", "Filename for association")
	associationCmd.Flags().String("base-info", "", "Base information for association")
	associationCmd.Flags().StringP("salt", "s", "", "Salt value")
	
	// Algorithm-specific parameters for association
	associationCmd.Flags().Int("pbkdf2-iterations", 10000, "PBKDF2 iteration count")
	associationCmd.Flags().Int("bcrypt-cost", 12, "Bcrypt cost parameter")
	associationCmd.Flags().Int("scrypt-n", 32768, "Scrypt N parameter")
	associationCmd.Flags().Int("scrypt-r", 8, "Scrypt R parameter") 
	associationCmd.Flags().Int("scrypt-p", 1, "Scrypt P parameter")
	associationCmd.Flags().Uint32("argon-time", 1, "Argon2 time parameter")
	associationCmd.Flags().Uint32("argon-memory", 65536, "Argon2 memory in KB")
	associationCmd.Flags().Uint8("argon-parallelism", 4, "Argon2 parallelism parameter")
	
	associationCmd.MarkFlagRequired("hash")

	rootCmd.AddCommand(crackCmd)
	rootCmd.AddCommand(batchCmd)
	rootCmd.AddCommand(webCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(combinationCmd)
	rootCmd.AddCommand(hybridCmd)
	rootCmd.AddCommand(associationCmd)

	viper.SetEnvPrefix("HASHCRACK")
	viper.AutomaticEnv()
	viper.SetDefault("workers", runtime.NumCPU())
}

func runCrack(cmd *cobra.Command, args []string) error {
	algo, _ := cmd.Flags().GetString("algorithm")
	targetHash, _ := cmd.Flags().GetString("hash")
	wordlist, _ := cmd.Flags().GetString("wordlist")
	maskPattern, _ := cmd.Flags().GetString("mask")
	minLen, _ := cmd.Flags().GetInt("min-length")
	maxLen, _ := cmd.Flags().GetInt("max-length")
	salt, _ := cmd.Flags().GetString("salt")
	rulesStr, _ := cmd.Flags().GetString("rules")
	
	// Read algorithm-specific parameters
	pbkdf2Iterations, _ := cmd.Flags().GetInt("pbkdf2-iterations")
	bcryptCost, _ := cmd.Flags().GetInt("bcrypt-cost")
	scryptN, _ := cmd.Flags().GetInt("scrypt-n")
	scryptR, _ := cmd.Flags().GetInt("scrypt-r")
	scryptP, _ := cmd.Flags().GetInt("scrypt-p")
	argonTime, _ := cmd.Flags().GetUint32("argon-time")
	argonMemory, _ := cmd.Flags().GetUint32("argon-memory")
	argonParallelism, _ := cmd.Flags().GetUint8("argon-parallelism")

	if algo == "auto" {
		detected := hashes.Detect(targetHash)
		if len(detected) == 0 {
			return fmt.Errorf("could not detect algorithm for hash: %s", targetHash)
		}
		algo = detected[0]
		fmt.Printf("Detected algorithm: %s\n", algo)
	}

	if ok, msg := hashes.Validate(algo, targetHash); !ok {
		if strings.TrimSpace(msg) == "" {
			msg = "selected algorithm does not match target hash format"
		}
		return fmt.Errorf("invalid input: %s (algo=%s)", msg, algo)
	}

	hasher, err := hashes.Get(algo)
	if err != nil {
		return err
	}

	var rules []string
	if rulesStr != "" {
		rules = strings.Split(rulesStr, ",")
	}

	numWorkers := viper.GetInt("workers")
	if workers > 0 {
		numWorkers = workers
	}

	c := cracker.New(cracker.Options{
		Workers: numWorkers,
		LogPath: logPath,
		Event: func(event string, kv map[string]any) {
			if verbose {
				fmt.Printf("[%s] ", event)
				for k, v := range kv {
					fmt.Printf("%s=%v ", k, v)
				}
				fmt.Println()
			}
		},
		Transform: buildTransform(rules),
	})
	defer c.Close()

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nInterrupted, stopping...")
		cancel()
	}()

	params := hashes.Params{
		Salt:             parseSalt(salt),
		BcryptCost:       bcryptCost,
		ScryptN:          scryptN,
		ScryptR:          scryptR,
		ScryptP:          scryptP,
		ArgonTime:        argonTime,
		ArgonMemoryKB:    argonMemory,
		ArgonParallelism: argonParallelism,
		PBKDF2Iterations: pbkdf2Iterations,
	}

	var result cracker.Result

	if maskPattern != "" {
		fmt.Printf("Starting mask attack with pattern: %s\n", maskPattern)
		gen, err := mask.NewGenerator(maskPattern)
		if err != nil {
			return err
		}
		result, err = gen.Crack(ctx, c, hasher, params, targetHash)
		if err != nil {
			return err
		}
	} else if wordlist != "" {
		fmt.Printf("Starting wordlist attack with: %s\n", wordlist)
		result, err = c.CrackWordlist(ctx, hasher, params, targetHash, wordlist)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("Starting brute force attack (length %d-%d)\n", minLen, maxLen)
		return fmt.Errorf("brute force mode requires either --wordlist or --mask")
	}

	// Print results
	fmt.Printf("\nResults:\n")
	fmt.Printf("  Tried: %d candidates\n", result.Tried)
	fmt.Printf("  Time: %v\n", result.Duration)
	fmt.Printf("  Speed: %.0f hashes/sec\n", float64(result.Tried)/result.Duration.Seconds())
	
	if result.Found {
		fmt.Printf("  Status: FOUND\n")
		fmt.Printf("  Password: %s\n", result.Plaintext)
		return nil
	} else {
		fmt.Printf("  Status: NOT FOUND\n")
		return fmt.Errorf("password not found")
	}
}

func runBatch(cmd *cobra.Command, args []string) error {
	batchFile, _ := cmd.Flags().GetString("file")
	wordlist, _ := cmd.Flags().GetString("wordlist")
	outputFile, _ := cmd.Flags().GetString("output")

	file, err := os.Open(batchFile)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Printf("Batch processing from %s\n", batchFile)
	if wordlist != "" {
		fmt.Printf("Using wordlist: %s\n", wordlist)
	}
	if outputFile != "" {
		fmt.Printf("Output to: %s\n", outputFile)
	}

	return fmt.Errorf("batch mode not yet fully implemented")
}

func runWeb(cmd *cobra.Command, args []string) error {
	addr, _ := cmd.Flags().GetString("addr")
	
	manager := web.NewManager()
	server := web.NewServer(manager)
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		log.Println("\nShutting down web server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manager.Shutdown(ctx)
	os.Exit(0)
	}()
    
	log.Printf("Open your browser at: http://localhost%s", addr)
    
	return server.Start(addr)
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

func runCombination(cmd *cobra.Command, args []string) error {
	algo, _ := cmd.Flags().GetString("algorithm")
	targetHash, _ := cmd.Flags().GetString("hash")
	wordlist1, _ := cmd.Flags().GetString("wordlist1")
	wordlist2, _ := cmd.Flags().GetString("wordlist2")
	separator, _ := cmd.Flags().GetString("separator")
	salt, _ := cmd.Flags().GetString("salt")

	if algo == "auto" {
		detected := hashes.Detect(targetHash)
		if len(detected) == 0 {
			return fmt.Errorf("could not detect algorithm for hash: %s", targetHash)
		}
		algo = detected[0]
		fmt.Printf("Detected algorithm: %s\n", algo)
	}

	hasher, err := hashes.Get(algo)
	if err != nil {
		return err
	}

	numWorkers := viper.GetInt("workers")
	if workers > 0 {
		numWorkers = workers
	}

	c := cracker.New(cracker.Options{
		Workers: numWorkers,
		LogPath: logPath,
		Event: func(event string, kv map[string]any) {
			if verbose {
				fmt.Printf("[%s] ", event)
				for k, v := range kv {
					fmt.Printf("%s=%v ", k, v)
				}
				fmt.Println()
			}
		},
	})
	defer c.Close()

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	params := hashes.Params{
		Salt:             parseSalt(salt),
		BcryptCost:       12,
		ScryptN:          32768,
		ScryptR:          8,
		ScryptP:          1,
		ArgonTime:        1,
		ArgonMemoryKB:    65536,
		ArgonParallelism: 4,
		PBKDF2Iterations: 10000,
	}

	opts := cracker.CombinationOptions{
		Wordlist1: wordlist1,
		Wordlist2: wordlist2,
		Separator: separator,
	}

	start := time.Now()
	result, err := c.CrackCombination(ctx, hasher, params, targetHash, opts)
	if err != nil {
		return err
	}

	duration := time.Since(start)
	fmt.Printf("Tried %d combinations in %v\n", result.Tried, duration)
	if result.Found {
		fmt.Printf("Password found: %s\n", result.Plaintext)
	} else {
		fmt.Println("Password not found")
	}

	return nil
}

func runHybrid(cmd *cobra.Command, args []string) error {
	algo, _ := cmd.Flags().GetString("algorithm")
	targetHash, _ := cmd.Flags().GetString("hash")
	wordlist, _ := cmd.Flags().GetString("wordlist")
	maskPattern, _ := cmd.Flags().GetString("mask")
	isPrefix, _ := cmd.Flags().GetBool("prefix")
	salt, _ := cmd.Flags().GetString("salt")

	if algo == "auto" {
		detected := hashes.Detect(targetHash)
		if len(detected) == 0 {
			return fmt.Errorf("could not detect algorithm for hash: %s", targetHash)
		}
		algo = detected[0]
		fmt.Printf("Detected algorithm: %s\n", algo)
	}

	hasher, err := hashes.Get(algo)
	if err != nil {
		return err
	}

	numWorkers := viper.GetInt("workers")
	if workers > 0 {
		numWorkers = workers
	}

	c := cracker.New(cracker.Options{
		Workers: numWorkers,
		LogPath: logPath,
		Event: func(event string, kv map[string]any) {
			if verbose {
				fmt.Printf("[%s] ", event)
				for k, v := range kv {
					fmt.Printf("%s=%v ", k, v)
				}
				fmt.Println()
			}
		},
	})
	defer c.Close()

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	params := hashes.Params{
		Salt:             parseSalt(salt),
		BcryptCost:       12,
		ScryptN:          32768,
		ScryptR:          8,
		ScryptP:          1,
		ArgonTime:        1,
		ArgonMemoryKB:    65536,
		ArgonParallelism: 4,
		PBKDF2Iterations: 10000,
	}

	opts := cracker.HybridOptions{
		Wordlist: wordlist,
		Mask:     maskPattern,
		IsPrefix: isPrefix,
	}

	start := time.Now()
	result, err := c.CrackHybrid(ctx, hasher, params, targetHash, opts)
	if err != nil {
		return err
	}

	duration := time.Since(start)
	fmt.Printf("Tried %d combinations in %v\n", result.Tried, duration)
	if result.Found {
		fmt.Printf("Password found: %s\n", result.Plaintext)
	} else {
		fmt.Println("Password not found")
	}

	return nil
}

func runAssociation(cmd *cobra.Command, args []string) error {
	algo, _ := cmd.Flags().GetString("algorithm")
	targetHash, _ := cmd.Flags().GetString("hash")
	username, _ := cmd.Flags().GetString("username")
	hint, _ := cmd.Flags().GetString("hint")
	filename, _ := cmd.Flags().GetString("filename")
	baseInfo, _ := cmd.Flags().GetString("base-info")
	salt, _ := cmd.Flags().GetString("salt")

	if algo == "auto" {
		detected := hashes.Detect(targetHash)
		if len(detected) == 0 {
			return fmt.Errorf("could not detect algorithm for hash: %s", targetHash)
		}
		algo = detected[0]
		fmt.Printf("Detected algorithm: %s\n", algo)
	}

	hasher, err := hashes.Get(algo)
	if err != nil {
		return err
	}

	numWorkers := viper.GetInt("workers")
	if workers > 0 {
		numWorkers = workers
	}

	c := cracker.New(cracker.Options{
		Workers: numWorkers,
		LogPath: logPath,
		Event: func(event string, kv map[string]any) {
			if verbose {
				fmt.Printf("[%s] ", event)
				for k, v := range kv {
					fmt.Printf("%s=%v ", k, v)
				}
				fmt.Println()
			}
		},
	})
	defer c.Close()

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	params := hashes.Params{
		Salt:             parseSalt(salt),
		BcryptCost:       12,
		ScryptN:          32768,
		ScryptR:          8,
		ScryptP:          1,
		ArgonTime:        1,
		ArgonMemoryKB:    65536,
		ArgonParallelism: 4,
		PBKDF2Iterations: 10000,
	}

	opts := cracker.AssociationOptions{
		Username: username,
		Hint:     hint,
		Filename: filename,
		BaseInfo: baseInfo,
	}

	start := time.Now()
	result, err := c.CrackAssociation(ctx, hasher, params, targetHash, opts)
	if err != nil {
		return err
	}

	duration := time.Since(start)
	fmt.Printf("Tried %d candidates in %v\n", result.Tried, duration)
	if result.Found {
		fmt.Printf("Password found: %s\n", result.Plaintext)
	} else {
		fmt.Println("Password not found")
	}

	return nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
