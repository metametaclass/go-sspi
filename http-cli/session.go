package main

import (
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/pkg/errors"
	"github.com/ssgreg/logf"
)

// HTTPSession represent authenticated http session API
type HTTPSession interface {
	io.Closer
	Do(req *http.Request) (*http.Response, error)
}

// NegotiateSession implements HTTPSession with Negotiate authentication
type NegotiateSession struct {
	logger  *logf.Logger
	cred    *sspi.Credentials
	ctx     *negotiate.ClientContext
	token   []byte
	client  *http.Client
	authErr error
	host    string
}

func NewNegotiateSession(logger *logf.Logger, domain, username, password string) (*NegotiateSession, error) {
	var cred *sspi.Credentials
	var err error
	if username == "" {
		cred, err = negotiate.AcquireCurrentUserCredentials()
	} else {
		cred, err = negotiate.AcquireUserCredentials(domain, username, password)
	}
	if err != nil {
		return nil, err
	}
	ctx, initialToken, err := negotiate.NewClientContext(cred, "")
	if err != nil {
		err1 := cred.Release()
		if err1 != nil {
			logger.Warn("NewNegotiateSession: cred.Release failed")
		}
		return nil, err
	}
	return &NegotiateSession{
		logger: logger,
		cred:   cred,
		ctx:    ctx,
		token:  initialToken,
		client: http.DefaultClient,
	}, nil
}

func (s *NegotiateSession) Close() error {
	err1 := s.ctx.Release()
	err2 := s.cred.Release()
	if err1 != nil && err2 != nil {
		return errors.Errorf("ctx.Release and cred.Release failed %s %s", err1, err2)
	}
	if err1 != nil {
		return err1
	}
	return err1
}

func (s *NegotiateSession) Do(req *http.Request) (*http.Response, error) {
	if s.authErr != nil {
		return nil, s.authErr
	}
	if s.host == "" {
		//first request
		s.host = req.Host
		s.logger = s.logger.With(logf.String("host", req.Host))
		logger := s.logger.With(logf.String("url", req.URL.String()), logf.String("method", req.Method))
		resp, err := s.authenticate(logger, req)
		if err != nil {
			// close sessions
			s.client.CloseIdleConnections()
			s.authErr = err
			return nil, err
		}
		// response should be completed on last leg of exchange
		return resp, nil
	} else if s.host != req.Host {
		return nil, errors.Errorf("Do: multiple hosts not supported: %s!=%s", s.host, req.Host)
	}
	s.logger.Debug("http_request", logf.String("url", req.URL.String()), logf.String("method", req.Method))
	// should we retry auth if subsequent calls returns 401, for example, after network connection reset?
	return s.client.Do(req)
}

func (s *NegotiateSession) authenticate(logger *logf.Logger, req *http.Request) (*http.Response, error) {
	for {
		resp, completed, err := s.authenticateStep(logger, req)
		if err != nil {
			return nil, err
		}
		if completed {
			return resp, nil
		}
	}
}

func (s *NegotiateSession) authenticateStep(logger *logf.Logger, req *http.Request) (*http.Response, bool, error) {
	// we should not send body before auth
	req1, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), nil)
	if err != nil {
		s.authErr = errors.Wrap(err, "NewRequestWithContext failed")
		return nil, false, s.authErr
	}
	authorization := "Negotiate " + base64.StdEncoding.EncodeToString(s.token)
	logger.Debug("authenticateStep: request", logf.String("authorization_header", authorization))
	// add token header
	req1.Header.Add("Authorization", authorization)
	resp1, err := s.client.Do(req1)
	if err != nil {
		s.authErr = errors.Wrap(err, "Do: client.Do failed")
		return nil, false, s.authErr
	}
	for k, v := range resp1.Header {
		for _, vv := range v {
			logger.Debug("header", logf.String("name", k), logf.String("value", vv))
		}
	}
	// server authenticated us without negotiation
	// or just returns an error?
	if resp1.StatusCode != 401 {
		logger.Warn("authenticateStep: unexpected status code",
			logf.Int("status_code", resp1.StatusCode),
			logf.String("status", resp1.Status),
		)
		// retry original request
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, false, errors.Wrap(err, "Do failed")
		}
		// close body in caller, as usual
		return resp, true, nil
	}
	// close body by ourselves
	defer resp1.Body.Close()

	body, err := ioutil.ReadAll(resp1.Body)
	if err != nil {
		s.logger.Warn("ReadAll failed", logf.Error(err))
	}
	logger.Debug("authenticateStep: body", logf.Bytes("body_bytes", body), logf.String("body", string(body)))
	authHeaders, found := resp1.Header["Www-Authenticate"]
	if !found {
		logger.Error("Www-Authenticate header not found")
		s.authErr = errors.Errorf("authentication failed")
		return nil, false, s.authErr
	}
	var negotiateData string
	for _, h := range authHeaders {
		if strings.HasPrefix(h, "Negotiate ") {
			negotiateData = h[10:]
		}
	}
	if negotiateData == "" {
		s.authErr = errors.Errorf("Www-Authenticate Negotiate header not found")
		return nil, false, s.authErr
	}
	logger.Debug("authenticateStep: token ", logf.String("negotiate_data", negotiateData))
	token, err := base64.StdEncoding.DecodeString(negotiateData)
	if err != nil {
		s.authErr = errors.Wrapf(err, "DecodeString failed for Negotiate header %s", negotiateData)
		return nil, false, s.authErr
	}
	completed, token, err := s.ctx.Update(token)
	if err != nil {
		return nil, false, err
	}
	if completed {
		// finish authentication and perform original request
		s.token = nil
		authorization := "Negotiate " + base64.StdEncoding.EncodeToString(token)
		logger.Debug("authenticateStep: finalize", logf.String("authorization_header", authorization))
		req.Header.Set("Authorization", authorization)
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, false, errors.Wrap(err, "Do failed")
		}
		return resp, true, nil
	}
	s.token = token
	return nil, false, nil
}
