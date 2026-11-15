package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Laky-64/appleservices/internal/egresspool"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: proxy-pool inspect | assign -account-dir PATH")
	}
	switch args[0] {
	case "inspect":
		if len(args) != 1 {
			return errors.New("usage: proxy-pool inspect")
		}
		snapshot, err := egresspool.Inspect()
		if err != nil {
			return err
		}
		return printJSON(snapshot)
	case "assign":
		flags := flag.NewFlagSet("assign", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		accountDir := flags.String("account-dir", "", "account data directory")
		if err := flags.Parse(args[1:]); err != nil {
			return errors.New("invalid assign arguments")
		}
		if *accountDir == "" || flags.NArg() != 0 {
			return errors.New("usage: proxy-pool assign -account-dir PATH")
		}
		route, err := egresspool.Resolve(*accountDir)
		if err != nil {
			return err
		}
		return printJSON(struct {
			Enabled bool   `json:"enabled"`
			Account string `json:"account"`
			NodeID  string `json:"node_id,omitempty"`
			ExitIP  string `json:"exit_ip,omitempty"`
		}{Enabled: route.Enabled, Account: accountLabel(*accountDir), NodeID: route.NodeID, ExitIP: route.ExitIP})
	default:
		return errors.New("usage: proxy-pool inspect | assign -account-dir PATH")
	}
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return errors.New("could not encode proxy pool summary")
	}
	return nil
}

func accountLabel(accountDir string) string {
	portable := strings.ReplaceAll(strings.TrimSpace(accountDir), `\`, "/")
	portable = strings.TrimRight(portable, "/")
	if portable == "" {
		return ""
	}
	if index := strings.LastIndexByte(portable, '/'); index >= 0 {
		portable = portable[index+1:]
	}
	return strings.ToLower(portable)
}
