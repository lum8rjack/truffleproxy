/*
Copyright © 2023 @lum8rjack
*/
package engine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
)

var (
	selectedScanners map[string]detectors.Detector
)

type ScanResult struct {
	Url           string
	Secrets_found int
	Secrets       []Secret
}

type Secret struct {
	Scanner  string
	Value    string
	Verified bool
}

// Scan the bytes for secrets
func ScanResponse(url string, body []byte, verify bool) (ScanResult, error) {
	result := ScanResult{
		Url:           url,
		Secrets_found: 0,
	}

	// Make sure the body isn't empty
	if len(body) <= 10 {
		return result, nil
	}

	// Loop through all the scanners
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour*2)
	var cancelOnce sync.Once
	defer cancelOnce.Do(cancel)
	for name, scanner := range selectedScanners {
		foundKeyword := false

		// Pre-filter based on keywords
		for _, keyword := range scanner.Keywords() {
			if strings.Contains(strings.ToLower(string(body)), strings.ToLower(keyword)) {
				foundKeyword = true
			}
		}

		// If nothing was found, continue with other scanners
		if !foundKeyword {
			continue
		}

		// Checks for the results
		detectorResults, err := scanner.FromData(ctx, verify, body)
		if err != nil {
			continue
		}

		// If atleast 1 result
		if len(detectorResults) > 0 {
			m := map[string]float64{}

			// Add result to map
			for _, result := range detectorResults {
				if len(result.Raw) != 0 {
					m[string(result.Raw)]++
				}
				if len(result.RawV2) != 0 {
					m[string(result.RawV2)]++
				}
			}

			// Loop over the map
			for secret := range m {
				newsecret := Secret{
					Scanner: name,
				}

				if verify {
					for _, result := range detectorResults {
						if strings.EqualFold(string(result.Raw), secret) {
							newsecret.Value = string(result.Raw)
							newsecret.Verified = result.Verified
							break
						} else if strings.EqualFold(string(result.RawV2), secret) {
							newsecret.Value = string(result.RawV2)
							newsecret.Verified = result.Verified
							break
						}
					}
				} else {
					newsecret.Value = secret
					newsecret.Verified = false
				}

				// add to the list of secrets
				result.Secrets = append(result.Secrets, newsecret)
			}
			//continue
		}
	}

	result.Secrets_found = len(result.Secrets)
	return result, nil
}

// Setup the scanners to use
func SetupScanners(scanners []string) (int, error) {
	if len(scanners) == 0 {
		return 0, errors.New("no scanners specified")
	}

	allScanners := map[string]detectors.Detector{}
	for _, s := range engine.DefaultDetectors() {
		secretType := reflect.Indirect(reflect.ValueOf(s)).Type().PkgPath()
		path := strings.Split(secretType, "/")[len(strings.Split(secretType, "/"))-1]

		for _, x := range scanners {
			if strings.EqualFold(path, x) {
				allScanners[path] = s
			}
		}
	}

	if len(allScanners) == 0 {
		return 0, errors.New("could not identify any scanners")
	}

	selectedScanners = allScanners
	return len(selectedScanners), nil
}

// Load all of the trufflehog scanners to use
func SetupAllScanners() int {
	allScanners := map[string]detectors.Detector{}
	for _, s := range engine.DefaultDetectors() {
		secretType := reflect.Indirect(reflect.ValueOf(s)).Type().PkgPath()
		path := strings.Split(secretType, "/")[len(strings.Split(secretType, "/"))-1]
		allScanners[path] = s
	}
	selectedScanners = allScanners
	return len(selectedScanners)
}
