/*
Copyright © 2023 @lum8rjack
*/
package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/lum8rjack/truffleproxy/engine"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	cert         string
	key          string
	exclude      string
	logfile      string
	onlyverified bool
	port         int
	scanners     string
	verbose      bool
	verify       bool
	domains      []string
)

// ProxyCmd represents the proxy command
var ProxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start the HTTP proxy",
	Long:  `Start the HTTP proxy in order to analyze the responses and check for secrets`,
	Run: func(cmd *cobra.Command, args []string) {
		start()
	},
}

func init() {
	ProxyCmd.Flags().StringVarP(&cert, "cert", "c", "truffleproxy.crt", "Certificate file to use")
	ProxyCmd.Flags().StringVarP(&exclude, "exclude", "e", "", "File containing domains to exclude")
	ProxyCmd.Flags().StringVarP(&key, "key", "k", "truffleproxy.key", "Key file to use")
	ProxyCmd.Flags().StringVarP(&logfile, "logfile", "l", "", "Log file to write to (default: none)")
	ProxyCmd.Flags().BoolVarP(&onlyverified, "only-verified", "o", false, "Only output secrets that were verified")
	ProxyCmd.Flags().IntVarP(&port, "port", "p", 9090, "Proxy port to listen on")
	ProxyCmd.Flags().StringVarP(&scanners, "scanners", "s", "", "Specify the scanners to use in a comma separated list (default all)")
	ProxyCmd.Flags().BoolVarP(&verbose, "verbose", "b", false, "Output all URLs that are being scanned not just ones identified as having secrets")
	ProxyCmd.Flags().BoolVarP(&verify, "verify", "v", false, "Verified identified secrets")
}

func start() {
	// Setup our own logging
	tlog, err := NewLogger(logfile)
	if err != nil {
		log.Fatal(err)
	}
	defer tlog.Sync()
	tlog.Info("started truffleproxy")

	// Check and confirm the self-signed cert/key
	certFile, err := os.ReadFile(cert)
	if err != nil {
		tlog.Fatal("error reading certificate file", zap.NamedError("error", err))
	}

	keyFile, err := os.ReadFile(key)
	if err != nil {
		tlog.Fatal("error reading certificate file", zap.NamedError("error", err))
	}

	tlog.Info("loaded certificate and key file")

	// Setup Proxy
	proxy, err := setupProxy(certFile, keyFile, exclude, tlog)
	if err != nil {
		tlog.Fatal("error creating proxy", zap.NamedError("error", err))
	}

	// Disable default goproxy logging warnings
	proxy.Logger = disableGoproxyWarnings()

	// Setup the trufflehog scanners
	if scanners == "" {
		n := engine.SetupAllScanners()
		tlog.Info("loaded scanners", zap.Int("num_scanners", n))
	} else {
		slist := strings.Split(scanners, ",")
		n, err := engine.SetupScanners(slist)
		if err != nil {
			tlog.Fatal("error loading scanners", zap.NamedError("error", err))
		}
		tlog.Info("loaded scanners", zap.Int("num_scanners", n))
	}

	// Verifying the results
	tlog.Info("verify secrets", zap.Bool("verify", verify))

	// Verbose output
	tlog.Info("verbose output", zap.Bool("verbose", verbose))

	// Start the proxy
	serverAddress := fmt.Sprintf(":%d", port)
	tlog.Info("starting proxy server", zap.String("address", serverAddress))
	tlog.Fatal("stopped truffleproxy", zap.Error(http.ListenAndServe(serverAddress, proxy)))
	tlog.Info("stopping truffleproxy")
}

// Sets the goproxy certificate
func setCA(caCert, caKey []byte) error {
	goproxyCa, err := tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return err
	}
	if goproxyCa.Leaf, err = x509.ParseCertificate(goproxyCa.Certificate[0]); err != nil {
		return err
	}

	goproxy.GoproxyCa = goproxyCa
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&goproxyCa)}

	return nil
}

// Check if we should scan the URL or not based on the excluded domains
func excludeDomain(host string) bool {
	var ex bool = false
	for _, d := range domains {
		if strings.Contains(host, d) {
			return true
		}
	}

	return ex
}

// Setup the http proxy
func setupProxy(certFile []byte, keyFile []byte, exclude string, tlog *zap.Logger) (*goproxy.ProxyHttpServer, error) {
	// Create goproxy
	tproxy := goproxy.NewProxyHttpServer()
	tproxy.Verbose = false

	// Setup certs
	setCA(certFile, keyFile)
	tproxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Check domains to exclude
	if exclude != "" {
		file, err := os.Open(exclude)
		if err != nil {
			return tproxy, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domains = append(domains, scanner.Text())
		}

		tlog.Info("loaded domains to exclude", zap.Int("domains_loaded", len(domains)))
	}

	/*
		We only need to parse the responses and we only want web related content (exclude pdf, binary, etc.)

		var IsWebRelatedText goproxy.RespCondition = goproxy.ContentTypeIs("text/html",
		"text/css",
		"text/javascript", "application/javascript",
		"text/xml",
		"text/json")

		Also added "text/plain" for text files, markdown, etc.
	*/
	tproxy.OnResponse(goproxy.ContentTypeIs("text/css", "text/javascript", "application/javascript", "text/xml", "text/json", "text/plain")).DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// Check if we should exclude this domain
		if excludeDomain(ctx.Req.Host) {
			return resp
		}

		// Get the body and send it to the engine to parse
		dump, err := httputil.DumpResponse(resp, true)
		if err == nil {
			n := len(dump)
			if n > 0 {
				go func() {
					res, _ := engine.ScanResponse(ctx.Req.URL.String(), dump, verify)
					if res.Secrets_found > 0 {
						if onlyverified {
							for _, s := range res.Secrets {
								if s.Verified {
									for _, s := range res.Secrets {
										tlog.Warn("secrets found", zap.String("url", res.Url), zap.String("scanner", s.Scanner), zap.String("value", s.Value), zap.Bool("verified", s.Verified))
									}
									break
								}
							}
						} else {
							for _, s := range res.Secrets {
								tlog.Warn("secrets found", zap.String("url", res.Url), zap.String("scanner", s.Scanner), zap.String("value", s.Value), zap.Bool("verified", s.Verified))
							}
						}
					} else {
						if verbose {
							tlog.Debug("scanned url", zap.String("url", res.Url))
						}
					}
				}()
			}
		}

		// Continue
		return resp
	})

	return tproxy, nil
}
