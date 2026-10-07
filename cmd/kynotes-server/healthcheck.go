package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Busnes-app/kynotes-server/internal/config"
)

const healthTimeout = 3 * time.Second

// healthcheckCommand probes GET /healthz on this server; exit 0 only on 200.
func healthcheckCommand(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	cfgPath := fs.String("config", "/data/kynotes.yaml", "config path")
	target := fs.String("url", "", "health URL (loopback only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: healthcheck [--config PATH] [--url URL]")
	}
	u := *target
	if u == "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		u, err = defaultHealthURL(c.Server.Bind)
		if err != nil {
			return err
		}
	}
	return probeHealth(u)
}

func defaultHealthURL(bind string) (string, error) {
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		return "", err
	}
	return "http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz", nil
}

func probeHealth(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return errors.New("healthcheck: url must be http://loopback-host:port/path")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("healthcheck: refusing non-loopback host %q", host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: status %d", resp.StatusCode)
	}
	return nil
}
