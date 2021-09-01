package main

import (
	"fmt"
	"os"

	"github.com/ssgreg/logf"
)

func CustomErrorEncoder(k string, e error, m logf.FieldEncoder) {
	var msg string
	if e == nil {
		msg = "<nil>"
	} else {
		msg = e.Error()
	}
	m.EncodeFieldString(k, msg)

	formatter, ok := e.(fmt.Formatter)
	if ok {
		verbose := fmt.Sprintf("%+v", formatter)
		if verbose != msg {
			m.EncodeFieldString(k+"_verbose", verbose)
		}
	}
}

var Encoder = logf.NewJSONEncoder(logf.JSONEncoderConfig{EncodeError: CustomErrorEncoder})

// newLogger instantiates Logger from ssgreg/logf, with corresponding close func.
func newLogger(config *Config) (*logf.Logger, logf.ChannelWriterCloseFunc) {

	level, ok := logf.LevelFromString(config.LogLevel)
	if !ok {
		// default value
		level = logf.LevelInfo
	}

	channelWriterConfig := logf.ChannelWriterConfig{
		Appender: logf.NewWriteAppender(os.Stderr, Encoder),
	}

	var writer logf.EntryWriter
	writer, closer := logf.NewChannelWriter(channelWriterConfig)

	logger := logf.NewLogger(level, writer)

	// name of the logging service
	logger = logger.WithName("http-cli")

	// if level is debug, show the file and line number of the caller
	if level == logf.LevelDebug {
		logger = logger.WithCaller()
	}

	return logger, closer
}
