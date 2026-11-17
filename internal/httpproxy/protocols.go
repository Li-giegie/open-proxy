package httpproxy

import "net/http"

// HTTP1OnlyProtocols 返回仅启用 HTTP/1.1 的协议集，用于承载正向代理
// 处理器的 http.Server：
//
//	srv := &http.Server{Handler: proxy, ...}
//	srv.Protocols = httpproxy.HTTP1OnlyProtocols()
//
// CONNECT 隧道依赖 Hijack 劫持连接，而 HTTP/2 的 ResponseWriter 不实现
// http.Hijacker，隧道无法建立（浏览器会因拿不到 200 而报握手/代理错误）。
// 显式声明只支持 HTTP/1.1 后，TLS ALPN 也只会协商 http/1.1；这取代了
// 旧的 TLSNextProto 空 map hack（那个只能抑制 TLS 监听上的 h2）。
func HTTP1OnlyProtocols() *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	return p
}
