package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sebdraven/heimdall/internal/config"
	"github.com/sebdraven/heimdall/internal/store/ch"
	"github.com/sebdraven/heimdall/internal/store/pg"
)

func main() {
	if err := run(); err != nil {
		slog.Error("heimdall-api failed", "err", err)
		os.Exit(1)
	}
}

func run() error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := cfg.Logger("api")
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	if cfg.Migrate {
		if err := pg.Migrate(ctx, cfg.PGDSN, log); err != nil {
			return err
		}
	}
	pgs, err := pg.Open(ctx, cfg.PGDSN)
	if err != nil {
		return err
	}
	defer pgs.Close()
	chs, err := ch.Open(ctx, ch.Options{Addr: cfg.CHAddr, Database: cfg.CHDatabase, User: cfg.CHUser, Password: cfg.CHPassword})
	if err != nil {
		return err
	}
	defer chs.Close()

	srv, err := newServer(cfg, log, pgs, chs)
	if err != nil {
		return err
	}
	if err := srv.loadCDN(ctx); err != nil {
		return err
	}
	go srv.housekeeping(ctx)
	go srv.reloadCDN(ctx)

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen)
		errc <- hs.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped")
	return nil
}
