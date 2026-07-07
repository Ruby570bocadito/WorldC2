package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents a log severity level.
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	FATAL
)

func (l Level) String() string {
	return []string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}[l]
}

// Entry represents a structured log entry.
type Entry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Logger is a structured logger with multiple outputs.
type Logger struct {
	mu       sync.Mutex
	level    Level
	outputs  []io.Writer
	fields   map[string]interface{}
	jsonMode bool
}

// New creates a new structured logger.
func New(level Level, jsonMode bool) *Logger {
	l := &Logger{
		level:    level,
		fields:   make(map[string]interface{}),
		jsonMode: jsonMode,
		outputs:  []io.Writer{os.Stderr},
	}
	return l
}

// With returns a new logger with additional fields.
func (l *Logger) With(fields map[string]interface{}) *Logger {
	newFields := make(map[string]interface{})
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}
	return &Logger{
		level:    l.level,
		outputs:  l.outputs,
		fields:   newFields,
		jsonMode: l.jsonMode,
	}
}

// AddOutput adds an additional output writer.
func (l *Logger) AddOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.outputs = append(l.outputs, w)
}

// SetLevel sets the minimum log level.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// log writes a log entry.
func (l *Logger) log(level Level, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level.String(),
		Message:   msg,
		Fields:    make(map[string]interface{}),
	}

	for k, v := range l.fields {
		entry.Fields[k] = v
	}
	for k, v := range fields {
		entry.Fields[k] = v
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, out := range l.outputs {
		if l.jsonMode {
			data, _ := json.Marshal(entry)
			fmt.Fprintln(out, string(data))
		} else {
			fmt.Fprintf(out, "[%s] [%s] %s", entry.Timestamp, entry.Level, entry.Message)
			if len(entry.Fields) > 0 {
				fmt.Fprintf(out, " %v", entry.Fields)
			}
			fmt.Fprintln(out)
		}
	}
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(DEBUG, msg, f)
}

// Info logs an info message.
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(INFO, msg, f)
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(WARN, msg, f)
}

// Error logs an error message.
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(ERROR, msg, f)
}

// Fatal logs a fatal message and exits.
func (l *Logger) Fatal(msg string, fields ...map[string]interface{}) {
	f := mergeFields(fields...)
	l.log(FATAL, msg, f)
	os.Exit(1)
}

func mergeFields(fields ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, f := range fields {
		for k, v := range f {
			result[k] = v
		}
	}
	return result
}
