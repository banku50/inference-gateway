package tests

import (
	"errors"
	"testing"

	"github.com/thirdwake/inference-gateway/logger"
	"github.com/thirdwake/inference-gateway/tests/mocks"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		wantErr bool
	}{
		{
			name:    "Development environment",
			env:     "development",
			wantErr: false,
		},
		{
			name:    "Production environment",
			env:     "production",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := logger.NewLogger(tt.env)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, log)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, log)

				// Verify logger functionality
				assert.NotPanics(t, func() {
					log.Info("test info")
					log.Debug("test debug")
					log.Error("test error", nil)
				})
			}
		})
	}
}

func TestLoggerMethods(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := mocks.NewMockLogger(ctrl)

	testCases := []struct {
		name    string
		setup   func()
		execute func(logger.Logger)
	}{
		{
			name: "Info logging",
			setup: func() {
				mockLogger.EXPECT().Info("test info", "key1", "value1")
			},
			execute: func(l logger.Logger) {
				l.Info("test info", "key1", "value1")
			},
		},
		{
			name: "Debug logging",
			setup: func() {
				mockLogger.EXPECT().Debug("test debug", "key1", "value1")
			},
			execute: func(l logger.Logger) {
				l.Debug("test debug", "key1", "value1")
			},
		},
		{
			name: "Error logging",
			setup: func() {
				mockLogger.EXPECT().Error("test error", gomock.Any(), "key1", "value1")
			},
			execute: func(l logger.Logger) {
				l.Error("test error", errors.New("test error"), "key1", "value1")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			tc.execute(mockLogger)
		})
	}
}
