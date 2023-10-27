/*
Copyright © 2023 @lum8rjack
*/
package scan

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/lum8rjack/truffleproxy/engine"
	"github.com/lum8rjack/truffleproxy/version"
	"github.com/spf13/cobra"
)

var (
	url       string
	useragent string
	scanners  string
	verify    bool
)

// ScanCmd represents the scan command
var ScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a single URL",
	Long:  `Send a web request to the provided URL and scan the response for secrets`,
	Run: func(cmd *cobra.Command, args []string) {
		if strings.HasPrefix(url, "http") {
			start()
		} else {
			cmd.Help()
		}
	},
}

func init() {
	useragent = fmt.Sprintf("truffleproxy-%s", version.VERSION)
	ScanCmd.Flags().StringVarP(&url, "url", "u", "", "URL to scan (required)")
	ScanCmd.Flags().StringVarP(&url, "useragent", "a", useragent, "User-agent to use when sending the request")
	ScanCmd.Flags().StringVarP(&scanners, "scanners", "s", "", "Specify the scanners to use in a comma separated list (default all)")
	ScanCmd.Flags().BoolVarP(&verify, "verify", "v", false, "Verified identified secrets (default false)")
}

func start() {
	// Setup the trufflehog scanners
	if scanners == "" {
		engine.SetupAllScanners()
	} else {
		slist := strings.Split(scanners, ",")
		_, err := engine.SetupScanners(slist)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Send a web request to the url
	client := http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", useragent)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()

	// Get the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// Scan the response body
	result, err := engine.ScanResponse(url, body, verify)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(result)
}
