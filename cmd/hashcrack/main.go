package main

import (
	"context"
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

var (
	workers  int
	timeout  time.Duration
	config   string
	logPath  string
	verbose  bool
)
// cleaner description
var rootCmd = &cobra.Command{
	Use:   "hashcrack",
	Short: "HashCrack - A fast, concurrent hash-cracking toolkit",
	Long: `HashCrack is a high-performance hash cracking tool designed for 
cybersecurity education and research purposes.`, 
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

func init() {
	// Global flags
	rootCmd.PersistentFlags().IntVarP(&workers, "workers", "w", 0, "Number of worker threads (default: CPU cores)")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 0, "Timeout for cracking attempts")
	rootCmd.PersistentFlags().StringVar(&config, "config", "", "Config file path")
	rootCmd.PersistentFlags().StringVar(&logPath, "log", "", "Log file path for events")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// crack command flags
	crackCmd.Flags().StringP("algorithm", "a", "auto", "Hash algorithm (auto-detect by default)")
	crackCmd.Flags().StringP("hash", "h", "", "Target hash to crack (required)")
	crackCmd.Flags().StringP("wordlist", "w", "", "Wordlist file path")
	crackCmd.Flags().StringP("mask", "m", "", "Mask pattern (e.g., ?l?l?l?d?d)")
	crackCmd.Flags().String("charset", "abcdefghijklmnopqrstuvwxyz0123456789", "Character set for brute force")
	crackCmd.Flags().Int("min-length", 1, "Minimum password length for brute force")
	crackCmd.Flags().Int("max-length", 6, "Maximum password length for brute force")
	crackCmd.Flags().String("salt", "", "Salt value (if applicable)")
	crackCmd.Flags().String("rules", "", "Comma-separated transformation rules (+u,+l,+c,+d1,+d2)")
	crackCmd.MarkFlagRequired("hash")

	// batch command flags
	batchCmd.Flags().StringP("file", "f", "", "Batch file path (required)")
	batchCmd.Flags().StringP("wordlist", "w", "", "Wordlist file path")
	batchCmd.Flags().String("output", "", "Output file for results")
	batchCmd.MarkFlagRequired("file")

	// web command flags
	webCmd.Flags().String("addr", ":8080", "Server address (host:port)")
	webCmd.Flags().String("static", "web/static", "Static files directory")
	webCmd.Flags().String("templates", "web/templates", "Template files directory")

	rootCmd.AddCommand(crackCmd)
	rootCmd.AddCommand(batchCmd)
	rootCmd.AddCommand(webCmd)
	rootCmd.AddCommand(listCmd)

	// Viper setup
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

	// auto-detect algorithm if needed
	if algo == "auto" {
		detected := hashes.Detect(targetHash)
		if len(detected) == 0 {
			return fmt.Errorf("could not detect algorithm for hash: %s", targetHash)
		}
		algo = detected[0]
		fmt.Printf("Detected algorithm: %s\n", algo)
	}

	// Validate algorithm vs target format before proceeding
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
		Salt: []byte(salt),
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

	// TODO: implement batch processing
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
		fmt.Println("\nShutting down web server...")
		os.Exit(0)
	}()
	
	fmt.Printf("Starting HashCrack Web UI on %s\n", addr)
	fmt.Printf("Open your browser and navigate to http://localhost%s\n", addr)
	
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

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
