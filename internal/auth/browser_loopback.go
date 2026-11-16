package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	loopbackCallbackPath = "/callback"
	loopbackDonePath     = "/done"
	loopbackFailedPath   = "/failed"
)

const loopbackDonePage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Flotte CLI</title></head>
<body><h1>Signed in</h1><p>You can close this tab and return to your terminal.</p></body></html>
`

const loopbackFailedPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Flotte CLI</title></head>
<body><h1>Sign-in was not completed</h1><p>Return to your terminal for details.</p></body></html>
`

type loopbackResult struct {
	code string
	err  error
}

type loopbackReceiver struct {
	redirectURI string
	host        string
	state       string
	issuer      string
	results     chan loopbackResult
	server      *http.Server
}

func startLoopbackReceiver(ctx context.Context, state, issuer string) (*loopbackReceiver, error) {
	listener, err := listenLoopback(ctx)
	if err != nil {
		return nil, err
	}
	host := listener.Addr().String()
	receiver := &loopbackReceiver{
		redirectURI: "http://" + host + loopbackCallbackPath,
		host:        host,
		state:       state,
		issuer:      issuer,
		results:     make(chan loopbackResult, 1),
	}
	receiver.server = &http.Server{
		Handler:           receiver,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() { _ = receiver.server.Serve(listener) }()
	return receiver, nil
}

func listenLoopback(ctx context.Context) (net.Listener, error) {
	config := loopbackListenConfig()
	listener, err := config.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err == nil {
		return listener, nil
	}
	listener, err6 := config.Listen(ctx, "tcp6", "[::1]:0")
	if err6 != nil {
		return nil, errors.Join(err, err6)
	}
	return listener, nil
}

func (l *loopbackReceiver) wait(ctx context.Context) (string, error) {
	select {
	case result := <-l.results:
		return result.code, result.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", errors.New("timed out waiting for the browser sign-in")
		}
		return "", errors.New("sign-in was cancelled")
	}
}

func (l *loopbackReceiver) close() {
	ctx, cancel := context.WithTimeout(context.Background(), loopbackShutdownGrace)
	defer cancel()
	if err := l.server.Shutdown(ctx); err != nil {
		_ = l.server.Close()
	}
}

func (l *loopbackReceiver) deliver(result loopbackResult) bool {
	select {
	case l.results <- result:
		return true
	default:
		return false
	}
}

func (l *loopbackReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Host != l.host {
		http.Error(w, "unexpected host", http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case loopbackCallbackPath:
		l.handleCallback(w, r)
	case loopbackDonePath:
		writeLoopbackPage(w, loopbackDonePage)
	case loopbackFailedPath:
		writeLoopbackPage(w, loopbackFailedPage)
	default:
		http.NotFound(w, r)
	}
}

func (l *loopbackReceiver) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(l.state)) != 1 {
		http.Error(w, "this response does not belong to the sign-in that the terminal is waiting for", http.StatusBadRequest)
		return
	}

	result := loopbackResult{code: query.Get("code")}
	switch {
	case query.Get("iss") != l.issuer:
		result = loopbackResult{err: errors.New("the sign-in response did not come from the configured Flotte server")}
	case query.Get("error") != "":
		result = loopbackResult{err: fmt.Errorf("sign-in was not completed: %s", describeOAuthError(query.Get("error"), query.Get("error_description")))}
	case result.code == "":
		result = loopbackResult{err: errors.New("the sign-in response did not contain a code")}
	}

	if !l.deliver(result) {
		http.Error(w, "this sign-in response was already received", http.StatusBadRequest)
		return
	}
	target := loopbackDonePath
	if result.err != nil {
		target = loopbackFailedPath
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func writeLoopbackPage(w http.ResponseWriter, page string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}
