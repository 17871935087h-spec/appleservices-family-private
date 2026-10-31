package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Laky-64/appleservices/internal/v2gateway"
)

func main() {
	listenAddr := flag.String("listen", envOr("V2GATEWAY_LISTEN_ADDR", v2gateway.DefaultListenAddr), "loopback listener address")
	dashboardURL := flag.String("dashboard", envOr("V2GATEWAY_DASHBOARD_URL", v2gateway.DefaultDashboard), "same-host dashboard URL")
	registryPath := flag.String("registry", os.Getenv("V2GATEWAY_REGISTRY"), "absolute dashboard accounts.json registry path")
	intentDir := flag.String("intent-dir", os.Getenv("V2GATEWAY_INTENT_DIR"), "absolute D: intent journal directory")
	flag.Parse()

	backend, err := v2gateway.New(v2gateway.Config{
		ListenAddr:   *listenAddr,
		DashboardURL: *dashboardURL,
		RegistryPath: *registryPath,
		IntentDir:    *intentDir,
		BearerToken:  os.Getenv("V2GATEWAY_BEARER_TOKEN"),
	})
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "v2gateway configuration failed\n")
		os.Exit(2)
	}
	defer backend.Close()
	listener, err := net.Listen("tcp4", *listenAddr)
	if err != nil {
		_, _ = io.WriteString(os.Stderr, "v2gateway listener failed\n")
		os.Exit(2)
	}
	server := &http.Server{
		Handler:           backend,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Preflight, one mutation and the two readbacks are sequential.
		WriteTimeout:   15 * time.Minute,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 8192,
		ErrorLog:       log.New(io.Discard, "", 0),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		_, _ = io.WriteString(os.Stderr, "v2gateway stopped\n")
		os.Exit(1)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
