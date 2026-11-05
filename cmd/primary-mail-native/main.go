// nativeheaders is a pipe-only adapter to the dashboard's nativeadi package.
// Its stdout contains sensitive verification headers and must only be captured
// by primary_mail.py in memory. It never receives Apple passwords or MME tokens.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Laky-64/appleservices/nativeadi"
	"howett.net/plist"
)

func main() {
	if !run() {
		os.Exit(1)
	}
}

func run() bool {
	dir := flag.String("account-dir", "", "D drive account directory")
	library := flag.String("adi-dll", "", "verified native library")
	python := flag.String("python", "", "existing Python runtime")
	flag.Parse()
	for _, path := range []string{*dir, *library, *python} {
		if !filepath.IsAbs(path) || !strings.EqualFold(filepath.VolumeName(path), "D:") {
			return false
		}
	}
	var device struct {
		Identifier   []byte
		SerialNumber string
	}
	data, err := os.ReadFile(filepath.Join(*dir, "device.json"))
	if err != nil || len(data) > 2<<20 || json.Unmarshal(data, &device) != nil || len(device.Identifier) != 16 || device.SerialNumber == "" {
		return false
	}
	profile := filepath.Join(*dir, "native-adi")
	var hardware struct {
		Push struct {
			Token []byte `plist:"token"`
		} `plist:"push"`
	}
	data, err = os.ReadFile(filepath.Join(profile, "hw_info.plist"))
	if err != nil || len(data) > 2<<20 {
		return false
	}
	if _, err = plist.Unmarshal(data, &hardware); err != nil || len(hardware.Push.Token) != 32 {
		return false
	}
	client, err := nativeadi.NewClient(nativeadi.Config{LibraryPath: *library, ProfileDir: profile, Python: *python,
		Identifier: device.Identifier, Serial: device.SerialNumber, PushToken: hardware.Push.Token})
	if err != nil {
		return false
	}
	// Headers has a separate 30-second deadline and Close may need five
	// seconds. Leave room for both before the supervisor's 60-second timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if client.Start(ctx) != nil {
		return false
	}
	defer client.Close()
	headers, err := client.Headers()
	if err != nil {
		return false
	}
	if json.NewEncoder(os.Stdout).Encode(headers) != nil {
		return false
	}
	return true
}
