/*
Copyright © 2023 @lum8rjack
*/
package proxy

import (
	"io"
	"log"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Disable default goproxy logging warnings
func disableGoproxyWarnings() *log.Logger {
	log := log.Default()
	log.SetFlags(0)
	log.SetOutput(io.Discard)

	return log
}

func NewLogger(logfile string) (*zap.Logger, error) {
	// Create a new logger configuration
	cfg := zap.NewDevelopmentConfig()
	cfg.Encoding = "json"

	cfg.EncoderConfig = zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "truffleproxy",
		MessageKey:     "msg",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Modify the logger configuration to use a human-readable timestamp format
	cfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02 15:04:05.000"))
	}

	// Set output to stdout if no logfile is provided
	if logfile == "" {
		cfg.OutputPaths = []string{"stdout"}
	} else {
		cfg.OutputPaths = []string{"stdout", logfile}
	}

	// Create a new logger with the modified configuration
	logger, err := cfg.Build()

	return logger, err
}
