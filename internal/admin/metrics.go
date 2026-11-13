package admin

import (
	"strconv"
	"sync"
	"time"
)

// recentCap 是"最近请求"环形记录的容量。
const recentCap = 50

// reqRecord 是一条最近请求记录。
type reqRecord struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user,omitempty"`
	Method string    `json:"method"`
	URL    string    `json:"url"`
	Status int       `json:"status,omitempty"`
}

// resourceMetrics 聚合单个资源的运行指标，实现 httpproxy.Metrics。
// 反向代理资源没有 httpproxy 埋点，由 metricsMiddleware 以相同的
// 回调喂数据，两类资源的视图因此一致。
type resourceMetrics struct {
	mu       sync.Mutex
	started  time.Time
	requests int64
	bytesIn  int64
	bytesOut int64
	byUser   map[string]int64
	byStatus map[int]int64
	recent   []reqRecord
}

func newResourceMetrics() *resourceMetrics {
	return &resourceMetrics{
		started:  time.Now(),
		byUser:   map[string]int64{},
		byStatus: map[int]int64{},
	}
}

// Request 实现 httpproxy.Metrics。
func (m *resourceMetrics) Request(user, method, url string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	if user != "" {
		m.byUser[user]++
	}
	m.recent = append(m.recent, reqRecord{
		Time: time.Now(), User: user, Method: method, URL: url,
	})
	if len(m.recent) > recentCap {
		m.recent = m.recent[len(m.recent)-recentCap:]
	}
}

// Response 实现 httpproxy.Metrics：计数并尽量把状态回填到最近的记录。
func (m *resourceMetrics) Response(status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byStatus[status]++
	if n := len(m.recent); n > 0 && m.recent[n-1].Status == 0 {
		m.recent[n-1].Status = status
	}
}

// BytesIn 实现 httpproxy.Metrics（客户端 → 目标方向）。
func (m *resourceMetrics) BytesIn(n int64) {
	if n == 0 {
		return
	}
	m.mu.Lock()
	m.bytesIn += n
	m.mu.Unlock()
}

// BytesOut 实现 httpproxy.Metrics（目标 → 客户端方向）。
func (m *resourceMetrics) BytesOut(n int64) {
	if n == 0 {
		return
	}
	m.mu.Lock()
	m.bytesOut += n
	m.mu.Unlock()
}

// MetricsView 是监控 API 的响应。
type MetricsView struct {
	StartedAt time.Time        `json:"started_at"`
	Requests  int64            `json:"requests"`
	BytesIn   int64            `json:"bytes_in"`
	BytesOut  int64            `json:"bytes_out"`
	ByUser    map[string]int64 `json:"by_user"`
	ByStatus  map[string]int64 `json:"by_status"`
	Recent    []reqRecord      `json:"recent"`
}

// view 返回当前快照（最近请求按时间倒序）。
func (m *resourceMetrics) view() MetricsView {
	m.mu.Lock()
	defer m.mu.Unlock()
	recent := make([]reqRecord, 0, len(m.recent))
	for i := len(m.recent) - 1; i >= 0; i-- {
		recent = append(recent, m.recent[i])
	}
	byStatus := make(map[string]int64, len(m.byStatus))
	for code, n := range m.byStatus {
		byStatus[strconv.Itoa(code)] = n
	}
	return MetricsView{
		StartedAt: m.started,
		Requests:  m.requests,
		BytesIn:   m.bytesIn,
		BytesOut:  m.bytesOut,
		ByUser:    cloneIntMap(m.byUser),
		ByStatus:  byStatus,
		Recent:    recent,
	}
}

func cloneIntMap(src map[string]int64) map[string]int64 {
	dst := make(map[string]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
