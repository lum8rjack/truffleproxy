/*
Copyright © 2023 @lum8rjack
*/
package cmd

import (
	"os"

	"github.com/lum8rjack/truffleproxy/cert"
	"github.com/lum8rjack/truffleproxy/proxy"
	"github.com/lum8rjack/truffleproxy/scan"
	"github.com/lum8rjack/truffleproxy/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "truffleproxy",
	Short: "HTTP proxy that uses trufflehog's engine to find secrets",
	Long:  ``,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func addSubcommandPallets() {
	rootCmd.AddCommand(cert.CertCmd)
	rootCmd.AddCommand(proxy.ProxyCmd)
	rootCmd.AddCommand(scan.ScanCmd)
	rootCmd.AddCommand(version.VersionCmd)
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	addSubcommandPallets()
}
