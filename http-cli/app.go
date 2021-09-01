package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptrace"
	"strings"

	"github.com/pkg/errors"
	"github.com/ssgreg/logf"
)

func Execute(config *Config) error {
	logger, loggerClose := newLogger(config)
	defer loggerClose()
	err := executeInner(logger, config)
	if err != nil {
		logger.Error("Execute: executeInner failed", logf.Error(err))
		return err
	}
	return nil
}

func executeInner(logger *logf.Logger, config *Config) error {
	session, err := NewNegotiateSession(logger, "", config.Username, config.Password)
	if err != nil {
		return err
	}
	defer func() {
		err = session.Close()
		if err != nil {
			logger.Warn("session.Close failed", logf.Error(err))
		}
	}()

	err = performRequest(logger, config, session)
	if err != nil {
		logger.Error("first request failed", logf.Error(err))
	}

	if config.Method != http.MethodPost {
		// repeat request for test
		err2 := performRequest(logger, config, session)
		if err2 != nil {
			logger.Error("second request failed", logf.Error(err2))
			return errors.Wrap(err2, "second request failed")
		}
	}

	return err
}

func performRequest(logger *logf.Logger, config *Config, session *NegotiateSession) error {
	context := context.Background()

	if config.IsTrace {
		trace := &httptrace.ClientTrace{
			DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
				logger.Debug("DNSDone", logf.Any("info", dnsInfo))
			},
			GotConn: func(connInfo httptrace.GotConnInfo) {
				logger.Debug("GotConn", logf.Any("info", connInfo))
			},
			PutIdleConn: func(err error) {
				logger.Debug("PutIdleConn", logf.Error(err))
			},
			GetConn: func(hostport string) {
				logger.Debug("GetConn", logf.String("hostport", hostport))
			},
			ConnectStart: func(network, addr string) {
				logger.Debug("ConnectStart", logf.String("network", network), logf.String("addr", addr))
			},
			ConnectDone: func(network, addr string, err error) {
				logger.Debug("ConnectDone", logf.String("network", network), logf.String("addr", addr), logf.Error(err))
			},
		}
		context = httptrace.WithClientTrace(context, trace)
	}

	req, err := http.NewRequestWithContext(context, config.Method, config.URL, strings.NewReader(config.Body))
	if err != nil {
		return errors.Wrap(err, "NewRequest")
	}
	for _, h := range config.Headers {
		pair := strings.SplitN(h, ":", 2)
		req.Header.Add(pair[0], pair[1])
	}
	resp, err := session.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			logger.Warn("Close failed", logf.Error(err))
		}
	}()

	fmt.Printf("Status: %d %s\n", resp.StatusCode, resp.Status)
	for k, v := range resp.Header {
		fmt.Printf("Header %s: %s\n", k, v)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "ReadAll failed")
	}

	if config.HexDump {
		fmt.Println(HexDump(body))
	} else {
		fmt.Println(string(body))
	}
	return nil
}
