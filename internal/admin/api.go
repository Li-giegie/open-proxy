package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed web/index.html
var webFS embed.FS

// sessions 是登录会话令牌的内存存储（进程重启后全部失效）。
type sessions struct {
	mu     sync.Mutex
	tokens map[string]time.Time // token → 过期时间
}

func newSessions() *sessions {
	return &sessions{tokens: map[string]time.Time{}}
}

// issue 签发一个新令牌。
func (s *sessions) issue() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.tokens[token] = time.Now().Add(sessionTTL)
	s.mu.Unlock()
	return token, nil
}

// valid 校验令牌并顺带延期。
func (s *sessions) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.tokens[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.tokens, token)
		return false
	}
	s.tokens[token] = time.Now().Add(sessionTTL)
	return true
}

// revoke 作废令牌。
func (s *sessions) revoke(token string) {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
}

// sessionTTL 是登录会话的有效期。
const sessionTTL = 12 * time.Hour

// Handler 返回管理中心的 HTTP 处理器：/api/* 为 REST API，/ 为 Web UI。
//
// 认证模型：user/password 均设置时启用认证。Web UI 登录页经
// POST /api/login 换取会话令牌，之后以 Bearer 携带；API 同时也接受
// 标准 Basic 认证（便于 curl 等工具）。静态页面本身不要求认证，
// 避免浏览器在加载 UI 时弹出原生登录框。
func Handler(m *Manager, user, password string) http.Handler {
	var sess *sessions
	if user != "" || password != "" {
		if user == "" || password == "" {
			panic("admin Handler: user 与 password 必须同时设置")
		}
		sess = newSessions()
	}

	requireAuth := func(r *http.Request) bool {
		if sess == nil {
			return true // 未配置认证：放行
		}
		auth := r.Header.Get("Authorization")
		scheme, cred, _ := strings.Cut(auth, " ")
		switch strings.ToLower(scheme) {
		case "basic":
			payload, err := base64.StdEncoding.DecodeString(cred)
			if err != nil {
				return false
			}
			u, p, _ := strings.Cut(string(payload), ":")
			userOK := subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1
			passOK := subtle.ConstantTimeCompare([]byte(p), []byte(password)) == 1
			return userOK && passOK
		case "bearer":
			return sess.valid(cred)
		}
		return false
	}

	unauthorized := func(w http.ResponseWriter) {
		// 不设置 WWW-Authenticate 头：该头会促使浏览器对 fetch 的 401
		// 弹出原生认证框。登录由前端登录页完成，curl 的 -u 也不依赖
		// 挑战头，删掉后没有任何功能损失。
		writeError(w, http.StatusUnauthorized, errors.New("未认证或凭证无效"))
	}

	mux := http.NewServeMux()

	// 登录换取会话令牌（未配置认证时直接放行）
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if sess == nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "auth": false})
			return
		}
		userOK := subtle.ConstantTimeCompare([]byte(req.User), []byte(user)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(req.Password), []byte(password)) == 1
		if !userOK || !passOK {
			unauthorized(w)
			return
		}
		token, err := sess.issue()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "auth": true, "token": token})
	})

	// 退出登录：作废会话
	mux.HandleFunc("DELETE /api/logout", func(w http.ResponseWriter, r *http.Request) {
		if sess != nil {
			_, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
			sess.revoke(strings.TrimSpace(token))
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /api/resources", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, m.List())
	})
	mux.HandleFunc("POST /api/resources", func(w http.ResponseWriter, r *http.Request) {
		var res Resource
		if err := readJSON(r, &res); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// ID 由服务端分配，忽略客户端传入值
		res.ID = ""
		view, err := m.Create(&res)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, view)
	})
	mux.HandleFunc("POST /api/resources/{id}/start", func(w http.ResponseWriter, r *http.Request) {
		view, err := m.Start(r.PathValue("id"))
		if err != nil {
			writeError(w, resourceErrStatus(r.PathValue("id"), err), err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	})
	mux.HandleFunc("POST /api/resources/{id}/stop", func(w http.ResponseWriter, r *http.Request) {
		view, err := m.Stop(r.PathValue("id"))
		if err != nil {
			writeError(w, resourceErrStatus(r.PathValue("id"), err), err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	})
	mux.HandleFunc("DELETE /api/resources/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := m.Delete(r.PathValue("id")); err != nil {
			writeError(w, resourceErrStatus(r.PathValue("id"), err), err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /api/resources/{id}/metrics", func(w http.ResponseWriter, r *http.Request) {
		view, err := m.Metrics(r.PathValue("id"))
		if err != nil {
			writeError(w, resourceErrStatus(r.PathValue("id"), err), err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	})

	mux.HandleFunc("GET /api/resources/{id}/users", func(w http.ResponseWriter, r *http.Request) {
		users, err := m.Users(r.PathValue("id"))
		if err != nil {
			writeError(w, resourceErrStatus(r.PathValue("id"), err), err)
			return
		}
		writeJSON(w, http.StatusOK, users)
	})
	mux.HandleFunc("POST /api/resources/{id}/users", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := m.AddUser(r.PathValue("id"), req.User, req.Password); err != nil {
			writeError(w, resourceErrStatus(r.PathValue("id"), err), err)
			return
		}
		users, _ := m.Users(r.PathValue("id"))
		writeJSON(w, http.StatusOK, users)
	})
	mux.HandleFunc("DELETE /api/resources/{id}/users/{user}", func(w http.ResponseWriter, r *http.Request) {
		if err := m.RemoveUser(r.PathValue("id"), r.PathValue("user")); err != nil {
			writeError(w, resourceErrStatus(r.PathValue("id"), err), err)
			return
		}
		users, _ := m.Users(r.PathValue("id"))
		writeJSON(w, http.StatusOK, users)
	})

	// 静态页面：不要求认证（登录逻辑在前端与 /api/login 完成），
	// 避免浏览器加载 UI 时弹出原生认证框
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := webFS.ReadFile("web/index.html")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/login" && !requireAuth(r) {
			unauthorized(w)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// resourceErrStatus 把 Manager 的错误映射为 HTTP 状态码：
// "不存在" → 404，其余（配置/端口问题）→ 400。
func resourceErrStatus(id string, err error) int {
	if strings.Contains(err.Error(), "不存在") {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

// readJSON 解析请求体，空 body 视为错误。
func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return errors.New("请求体需要是合法 JSON: " + err.Error())
	}
	return nil
}

// writeJSON 输出 JSON 响应。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError 输出 {"error": "..."} 形式的错误响应。
func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
