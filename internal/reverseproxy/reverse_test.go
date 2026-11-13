package reverseproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestForward(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotHost   string
		gotXFF    string
		gotBody   string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotHost = r.Method, r.URL.Path, r.Host
		gotXFF = r.Header.Get("X-Forwarded-For")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("X-Upstream", "yes")
		_, _ = w.Write([]byte("resp body"))
	}))
	defer upstream.Close()

	handler, err := New([]string{upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	req, _ := http.NewRequest(http.MethodPost, proxySrv.URL+"/a/b?x=1", strings.NewReader("req body"))
	req.Host = "app.example.com" // 客户端自带的域名，应透传到后端
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Errorf("upstream response header not forwarded")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "resp body" {
		t.Errorf("body = %q", body)
	}
	if gotMethod != http.MethodPost || gotPath != "/a/b" {
		t.Errorf("upstream saw %s %s", gotMethod, gotPath)
	}
	if gotBody != "req body" {
		t.Errorf("request body = %q", gotBody)
	}
	if gotHost != "app.example.com" {
		t.Errorf("Host = %q, want original host preserved", gotHost)
	}
	if gotXFF == "" {
		t.Errorf("missing X-Forwarded-For")
	}
}

func TestRoundRobin(t *testing.T) {
	var c1, c2 atomic.Int32
	u1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c1.Add(1)
	}))
	defer u1.Close()
	u2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c2.Add(1)
	}))
	defer u2.Close()

	handler, err := New([]string{u1.URL, u2.URL})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	for i := 0; i < 6; i++ {
		resp, err := client.Get(proxySrv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if c1.Load() != 3 || c2.Load() != 3 {
		t.Errorf("round robin: u1=%d u2=%d, want 3/3", c1.Load(), c2.Load())
	}
}

func TestUpstreamDown(t *testing.T) {
	handler, err := New([]string{"http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	resp, err := http.Get(proxySrv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Errorf("no backend: want error")
	}
	if _, err := New([]string{"::::"}); err == nil {
		t.Errorf("bad url: want error")
	}
	if _, err := New([]string{"ftp://host"}); err == nil {
		t.Errorf("bad scheme: want error")
	}
	if _, err := New([]string{"http://"}); err == nil {
		t.Errorf("no host: want error")
	}
}
