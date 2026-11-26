package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type consentTestServer struct {
	*httptest.Server
	answers []consentTestAnswer
	forms   []url.Values
	starts  []url.Values
	mu      sync.Mutex
}

const consentTestTicket = "1795651200.ticket-from-the-server"

type consentTestAnswer struct {
	body   string
	status int
}

func pendingAnswer() consentTestAnswer {
	return consentTestAnswer{status: http.StatusBadRequest, body: `{"error":"authorization_pending"}`}
}

func tokenAnswer(token string) consentTestAnswer {
	return consentTestAnswer{status: http.StatusOK, body: `{"access_token":"` + token + `","token_type":"Bearer"}`}
}

func newConsentTestServer(t *testing.T, answers ...consentTestAnswer) *consentTestServer {
	t.Helper()
	s := &consentTestServer{answers: answers}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth/cli/start") {
			s.mu.Lock()
			s.starts = append(s.starts, r.PostForm)
			s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ticket":"` + consentTestTicket + `"}`))
			return
		}
		if r.URL.Path != "/auth/cli/token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		s.forms = append(s.forms, r.PostForm)
		answer := s.answers[min(len(s.forms), len(s.answers))-1]
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(answer.status)
		_, _ = w.Write([]byte(answer.body))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *consentTestServer) requests() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.forms...)
}

func (s *consentTestServer) startRequests() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.starts...)
}
