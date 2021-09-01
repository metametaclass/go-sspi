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
	client := http.Client{
		//Transport: ,
	}

	req, err := http.NewRequest(config.Method, config.URL, strings.NewReader(config.Body))
	if err != nil {
		return errors.Wrap(err, "NewRequest")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "client.Do")
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			logger.Warn("Close failed", logf.Error(err))
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "ReadAll failed")
	}

	fmt.Println(body)
	return nil
}
