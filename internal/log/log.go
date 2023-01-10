package log

import "github.com/vela-security/vela-public/assert"

var xEnv assert.Environment

func WithEnv(env assert.Environment) {
	xEnv = env
}

// Errorf takes a formatted template string and template arguments for the error xEnvging level.
func Errorf(format string, args ...interface{}) {
	xEnv.Errorf(format, args...)
}

// Error xEnvs the given arguments at the error logging level.
func Error(args ...interface{}) {
	xEnv.Error(args...)
}

// Warnf takes a formatted template string and template arguments for the warning xEnvging level.
func Warnf(format string, args ...interface{}) {
	xEnv.Warnf(format, args...)
}

// Warn xEnvs the given arguments at the warning logging level.
func Warn(args ...interface{}) {
	xEnv.Warn(args...)
}

// Infof takes a formatted template string and template arguments for the info xEnvging level.
func Infof(format string, args ...interface{}) {
	xEnv.Infof(format, args...)
}

// Info xEnvs the given arguments at the info logging level.
func Info(args ...interface{}) {
	xEnv.Info(args...)
}

// Debugf takes a formatted template string and template arguments for the debug xEnvging level.
func Debugf(format string, args ...interface{}) {
	xEnv.Debugf(format, args...)
}

// Debug xEnvs the given arguments at the debug logging level.
func Debug(args ...interface{}) {
	xEnv.Debug(args...)
}
