package main

import (
	stdlog "log"

	"github.com/spf13/cobra"
)

func main() {
	err := NewRootCommand().Execute()
	if err != nil {
		stdlog.Fatalf("main: error %+v", err)
	}
}

func NewRootCommand() *cobra.Command {
	cfg := NewConfig()

	rootCmd := &cobra.Command{
		Use:  "http-cli -m method -b body url",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.URL = args[0]
			return Execute(cfg)
		},
		Example:      "http-cli -m POST -b \"{}\" http://127.0.0.1:5985/wsman",
		SilenceUsage: true,
	}
	rootCmd.PersistentFlags().StringVarP(&cfg.LogLevel, "level", "l", "info", "log level")
	rootCmd.PersistentFlags().StringVarP(&cfg.Method, "method", "m", "GET", "method")
	rootCmd.PersistentFlags().StringVarP(&cfg.Body, "body", "b", "", "body")
	rootCmd.PersistentFlags().BoolVarP(&cfg.HexDump, "hex", "x", false, "show response hex dump")
	rootCmd.PersistentFlags().StringVarP(&cfg.Username, "username", "u", "", "username")
	rootCmd.PersistentFlags().StringVarP(&cfg.Password, "password", "p", "", "password")
	rootCmd.PersistentFlags().StringVarP(&cfg.Package, "package", "P", "", "password")
	rootCmd.PersistentFlags().StringArrayVarP(&cfg.Headers, "headers", "H", nil, "additional headers")

	return rootCmd
}
