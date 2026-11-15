// macpushcheck verifies an account-isolated Apple APS certificate/token without
// logging in to an account, requesting SMS, or accepting a notification.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Laky-64/appleservices"
	"github.com/Laky-64/appleservices/aps"
	"github.com/Laky-64/appleservices/internal/egresspool"
	"github.com/google/uuid"
	"howett.net/plist"
)

func run() error {
	dir := flag.String("dir", "", "bound account directory")
	profile := flag.String("profile", "", "explicit bound native hardware profile")
	state := flag.String("state", "", "private account APS state")
	flag.Parse()
	if err := egresspool.Apply(*dir); err != nil {
		return err
	}
	var device appleservices.Device
	data, err := os.ReadFile(filepath.Join(*dir, "device.json"))
	if err != nil || json.Unmarshal(data, &device) != nil || len(device.Identifier) != 16 {
		return errors.New("bound device unavailable")
	}
	var hardware struct {
		OSConfig struct {
			DeviceID string `plist:"device_id"`
		} `plist:"os_config"`
		Push struct {
			Token []byte `plist:"token"`
		} `plist:"push"`
	}
	data, err = os.ReadFile(filepath.Join(*profile, "hw_info.plist"))
	if err != nil {
		return errors.New("bound hardware unavailable")
	}
	if _, err := plist.Unmarshal(data, &hardware); err != nil || !strings.EqualFold(hardware.OSConfig.DeviceID, uuid.UUID(device.Identifier).String()) {
		return errors.New("push hardware does not match the selected device")
	}
	var saved aps.State
	data, err = os.ReadFile(*state)
	if err != nil || json.Unmarshal(data, &saved) != nil || !bytes.Equal(saved.Token, hardware.Push.Token) {
		return errors.New("push token does not match the bound hardware")
	}
	client, err := aps.NewClient(saved)
	if err != nil {
		return errors.New("account APS key/certificate validation failed")
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		return errors.New("account Mac APS courier connection failed")
	}
	if !bytes.Equal(client.State().Token, saved.Token) {
		return errors.New("APS changed token; explicit device rebinding required")
	}
	fmt.Println("Go Mac APS connected; certificate/key matched; bound-device=true; token stable=true; no account login or SMS")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
