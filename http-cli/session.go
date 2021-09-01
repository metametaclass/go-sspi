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
		resp, err := s.authenticate(req)
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

	// should we retry auth if subsequent calls returns 401, for example, after network connection reset?
	return s.client.Do(req)
}

func (s *NegotiateSession) authenticate(req *http.Request) (*http.Response, error) {
	for {
		resp, completed, err := s.authenticateStep(req)
		if err != nil {
			return nil, err
		}
		if completed {
			return resp, nil
		}
	}
}

func (s *NegotiateSession) authenticateStep(req *http.Request) (*http.Response, bool, error) {
	// we should not send body before auth
	req1, err := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), nil)
	if err != nil {
		s.authErr = errors.Wrap(err, "NewRequestWithContext failed")
		return nil, false, s.authErr
	}
	// add token header
	req1.Header.Add("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(s.token))
	resp1, err := s.client.Do(req1)
	if err != nil {
		s.authErr = errors.Wrap(err, "Do: client.Do failed")
		return nil, false, s.authErr
	}
	// server authenticated us without negotiation
	// or just returns an error?
	if resp1.StatusCode != 401 {
		s.logger.Warn("authenticateStep: unexpected status code",
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
	// close body by ourself
	defer resp1.Body.Close()
	// we don`t need body of auth exchange
	_, err = ioutil.ReadAll(resp1.Body)
	if err != nil {
		s.logger.Warn("ReadAll failed", logf.Error(err))
	}
	authHeaders, found := resp1.Header["Www-Authenticate"]
	if !found {
		s.authErr = errors.Errorf("Www-Authenticate header not found")
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
		//req1.Header.Add("Www-Authenticate", base64.StdEncoding.EncodeToString(s.initialToken))
		s.token = nil
		req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, false, errors.Wrap(err, "Do failed")
		}
		return resp, true, nil
	}
	s.token = token
	return nil, false, nil
}
