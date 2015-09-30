package main

import (
	"fmt"
	"net/http"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/dhiltgen/golang-tofu"
)

func main() {
	log.SetLevel(log.DebugLevel)

	if len(os.Args) < 2 {
		fmt.Println("You must specify a host[:port] as the first argument")
		os.Exit(1)
	}

	details, err := tofu.GetFingerprints(os.Args[1])
	if err != nil {
		fmt.Printf("Failed to get fingerprints: %s\n", err)
		os.Exit(1)
	} else {
		for i, detail := range details {
			fmt.Printf("%02d: Subject:      \"%s\"\n", i, detail.Subject)
			fmt.Printf("%02d: Issuer:       \"%s\"\n", i, detail.Issuer)
			fmt.Printf("%02d: Fingerprint:  \"%s\"\n", i, detail.Fingerprint)
		}
	}

	// Do your "user validation" here to establish trust with the cert(s)
	trustedFingerprint := details[0].Fingerprint

	httpClient, err := tofu.GetTofuClient(trustedFingerprint)
	if err != nil {
		fmt.Printf("Failed to get Trust-On-First-Use client: %s\n", err)
		os.Exit(1)
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", os.Args[1]), nil)
	if err != nil {
		fmt.Printf("Failed to get build request: %s\n", err)
		os.Exit(1)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("Failed to get do request: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Response code: %d\n", resp.StatusCode)
}
