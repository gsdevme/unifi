package cmd

import (
	"fmt"
	"github.com/google/martian/log"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "Unifi API inspector",
	Short: "A simple utilty to interact with the Unifi API",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
	},
}

func init() {
	if len(os.Getenv("DEBUG")) > 0 {
		log.SetLevel(log.Debug)
	}

	rootCmd.AddCommand(NewAuthCommand())
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
