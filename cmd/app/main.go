package main

import (
	"auth_service/internal/config"
	http_server "auth_service/internal/http-server"
	lg "auth_service/internal/logger"
	"auth_service/internal/service"
	"auth_service/internal/storage/pg"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sync/errgroup"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg := config.MustLoad(".env")
	logger := lg.NewLogger(slog.LevelDebug)
	logger.Info("config loaded", "cfg", cfg)
	storage, err := pg.New(cfg)
	if err != nil {
		logger.Error("Error connecting to database", "err", err)
		os.Exit(1)
	}
	defer storage.Close()
	services := service.NewServices(logger, cfg, storage)
	mainCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv := http_server.New(logger, cfg, services)
	g, gCtx := errgroup.WithContext(mainCtx)
	logger.Info("starting server...")
	g.Go(func() error {
		if err := srv.Run(gCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server run error: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		<-gCtx.Done()
		return srv.Shutdown(gCtx)
	})
	if err := g.Wait(); err != nil {
		logger.Error("error during server shutdown", "err", err)
		return
	}
	logger.Info("server shutdown")
}
