/*
Copyright © 2023 @lum8rjack
*/
package version

import (
	"fmt"

	"github.com/spf13/cobra"
)

var VERSION string = "2023.10.2"

// VersionCmd represents the version command
var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Long:  "truffleproxy version - print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("truffleproxy version %s\n", VERSION)
	},
}
