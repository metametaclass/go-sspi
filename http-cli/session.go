package main

import (
	"encoding/base64"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
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
	step    int
}

func NewNegotiateSession(logger *logf.Logger, domain, username, password string) (*NegotiateSession, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Jar: jar,
	}

	var cred *sspi.Credentials
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
		client: client,
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
			// close TCP connections
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
			if resp != nil {
				consumeBody(logger, resp.Body)
			}
			return nil, err
		}
		if completed {
			return resp, nil
		}
		s.step++
	}
}

func (s *NegotiateSession) authenticateStep(logger *logf.Logger, req *http.Request) (*http.Response, bool, error) {
	// we should not send body before auth
	var requestBody io.Reader
	if s.step > 1 {
		requestBody = req.Body
	}
	req1, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), requestBody)
	if err != nil {
		return nil, false, errors.Wrap(err, "NewRequestWithContext failed")
	}
	authorization := "Negotiate " + base64.StdEncoding.EncodeToString(s.token)
	logger.Debug("authenticateStep: request", logf.String("authorization_header", authorization))
	// add token header
	req1.Header.Add("Authorization", authorization)
	resp1, err := s.client.Do(req1)
	if err != nil {
		return nil, false, errors.Wrap(err, "Do: client.Do failed")
	}

	for k, v := range resp1.Header {
		for _, vv := range v {
			logger.Debug("header", logf.String("name", k), logf.String("value", vv))
		}
	}
	negotiateData, err := findNegotiateHeader(logger, resp1)
	if err != nil {
		// we return not-nil response on error to consume and close body in one place
		return resp1, false, err
	}

	completed := true
	if negotiateData != "" {
		logger.Debug("authenticateStep: token ", logf.String("negotiate_data", negotiateData))
		serverToken, err := base64.StdEncoding.DecodeString(negotiateData)
		if err != nil {
			return resp1, false, errors.Wrapf(err, "DecodeString failed for Negotiate header %s", negotiateData)
		}
		var token []byte
		completed, token, err = s.ctx.Update(serverToken)
		if err != nil {
			return resp1, false, err
		}
		s.token = token
	}

	// server authenticated us
	if resp1.StatusCode != http.StatusUnauthorized && completed {
		// close body in caller, as usual
		return resp1, true, nil
	}
	// close body by ourselves
	consumeBody(logger, resp1.Body)

	// not completed, but status code is not 401
	if resp1.StatusCode != http.StatusUnauthorized {
		s.authErr = errors.Errorf("Authentication not completed with incorrect status code %d %s", resp1.StatusCode, resp1.Status)
		return nil, false, s.authErr
	}
	// continue authentication exchange

	return nil, false, nil
}

func findNegotiateHeader(logger *logf.Logger, resp *http.Response) (string, error) {
	negotiateData := ""
	hasNegotiate := false
	authHeaders, found := resp.Header["Www-Authenticate"]

	if found {
		for _, h := range authHeaders {
			hasNegotiate = strings.HasPrefix(h, "Negotiate")
			if hasNegotiate {
				if len(h) >= 10 {
					negotiateData = h[10:]
				}
				break
			}
		}
	}

	// has negotiate data in header or there is no need for data
	if negotiateData != "" || resp.StatusCode != http.StatusUnauthorized {
		return negotiateData, nil
	}

	// process possible errors
	switch {
	case !found:
		// no header at all
		logger.Error("Www-Authenticate header not found")
		return "", errors.Errorf("authentication failed: Www-Authenticate header not found")
	case hasNegotiate:
		// empty Www-Authenticate negotiate header - server doesn`t like our initial token
		logger.Error("Negotiate without token, invalid credentials")
		return "", errors.Errorf("authentication failed: invalid credentials")
	default:
		// has other headers but no Negotiate
		logger.Error("Www-Authenticate Negotiate header not found. Negotiate is not supported")
		return "", errors.Errorf("authentication failed: negotiate is not supported")
	}
}

func consumeBody(logger *logf.Logger, body io.ReadCloser) {
	defer func() {
		err := body.Close()
		if err != nil {
			logger.Warn("consumeBody: Close failed", logf.Error(err))
		}
	}()

	bodyBytes, err := ioutil.ReadAll(body)
	if err != nil {
		logger.Warn("consumeBody: ReadAll failed", logf.Error(err))
	}
	logger.Debug("consumeBody", logf.Bytes("body_bytes", bodyBytes), logf.String("body", string(bodyBytes)))
}
