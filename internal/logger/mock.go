package logger

import (
	"context"
	"log/slog"
)

type mockLogger struct{}

func NewMockLogger() slog.Handler {
	return &mockLogger{}
}

func (m mockLogger) Enabled(context.Context, slog.Level) bool {
	return false
}

func (m mockLogger) Handle(context.Context, slog.Record) error {
	return nil
}

func (m mockLogger) WithAttrs([]slog.Attr) slog.Handler {
	return m
}

func (m mockLogger) WithGroup(string) slog.Handler {
	return m
}
