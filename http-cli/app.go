package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
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
	session, err := NewNegotiateSession(logger, "", "", "")
	if err != nil {
		return err
	}
	defer func() {
		err = session.Close()
		if err != nil {
			logger.Warn("session.Close failed", logf.Error(err))
		}
	}()

	req, err := http.NewRequest(config.Method, config.URL, strings.NewReader(config.Body))
	if err != nil {
		return errors.Wrap(err, "NewRequest")
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

	fmt.Printf("%d %s\n", resp.StatusCode, resp.Status)
	for k, v := range resp.Header {
		fmt.Printf("%s: %s\n", k, v)
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
