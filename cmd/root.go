/*
Copyright © 2026 Motalleb Fallahnezhad

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/fmotalleb/go-tools/git"
	"github.com/fmotalleb/go-tools/log"
	"github.com/fmotalleb/go-tools/reloader"
	"github.com/spf13/cobra"

	"github.com/fmotalleb/helios-dns/config"
	"github.com/fmotalleb/helios-dns/server"
)

var (
	debug = false
	cfIps = []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
	}
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "helios-dns",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Version: git.String(),
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		if debug {
			log.SetDebugDefaults()
		}
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		var configFile string
		var err error
		if configFile, err = cmd.Flags().GetString("config"); err != nil {
			return err
		}

		ctx, cancel := signal.NotifyContext(
			context.Background(),
			os.Kill, os.Interrupt,
		)
		defer cancel()
		ctx, err = log.WithNewEnvLogger(ctx)
		if err != nil {
			return err
		}
		var args map[string]any
		args, err = buildArgsMap(cmd)
		if err != nil {
			return err
		}
		reloader.WithOsSignal(ctx, func(ctx context.Context) error {
			var cfg config.Config
			if err = config.Parse(ctx, &cfg, configFile, args); err != nil {
				return err
			}
			return server.Serve(ctx, cfg)
		},
			time.Second*15,
		)

		return err
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// init initializes command-line flags for the root command, including configuration file path, format, debug mode, and dry-run options.
func init() {
	rootCmd.PersistentFlags().BoolVarP(&debug, "verbose", "v", false, "enable debug logging")
	rootCmd.Flags().StringP("config", "c", "", "config file, if config has a value set, argument for that value will be ignored")
	rootCmd.Flags().StringP("listen", "l", "127.0.0.1:5353", "listen address of dns server")
	rootCmd.Flags().Duration("interval", 10*time.Minute, "update interval for records")
	rootCmd.Flags().StringArray("cidr", cfIps, "CIDRs to test against")
	rootCmd.Flags().DurationP("timeout", "t", time.Second, "timeout of execution for each IP")
	rootCmd.Flags().String("sni", "", "sni address to check response against")
	rootCmd.Flags().Int("port", 443, "port to test against")
	rootCmd.Flags().Int("status", 0, "http status code expected from server, (zero means no http check)")

	rootCmd.Flags().Int("min-count", 1, "minimum IP samples from each CIDR")
	rootCmd.Flags().Int("max-count", 30, "maximum IP samples from each CIDR")
	rootCmd.Flags().Float64("chance", 0.05, "chance of picking each IP sample from CIDR")

	rootCmd.Flags().StringP("output", "o", "", "output file (only success results are saved)")
}

func buildArgsMap(cmd *cobra.Command) (map[string]any, error) {
	result := make(map[string]any)
	args := make(map[string]any)
	result["args"] = args

	var err error

	if args["cidrs"], err = cmd.Flags().GetStringArray("cidr"); err != nil {
		return nil, err
	}

	if args["sni"], err = cmd.Flags().GetString("sni"); err != nil {
		return nil, err
	}

	if args["listen"], err = cmd.Flags().GetString("listen"); err != nil {
		return nil, err
	}

	var timeout time.Duration
	if timeout, err = cmd.Flags().GetDuration("timeout"); err != nil {
		return nil, err
	}
	// store as seconds (matches Config.Timeout int)
	args["timeout"] = timeout.Nanoseconds()

	var interval time.Duration
	if interval, err = cmd.Flags().GetDuration("interval"); err != nil {
		return nil, err
	}
	args["interval"] = interval.Nanoseconds()

	if args["port"], err = cmd.Flags().GetInt("port"); err != nil {
		return nil, err
	}

	if args["status_code"], err = cmd.Flags().GetInt("status"); err != nil {
		return nil, err
	}

	if args["sample_min"], err = cmd.Flags().GetInt("min-count"); err != nil {
		return nil, err
	}

	if args["sample_max"], err = cmd.Flags().GetInt("max-count"); err != nil {
		return nil, err
	}

	if args["sample_chance"], err = cmd.Flags().GetFloat64("chance"); err != nil {
		return nil, err
	}

	return result, nil
}
