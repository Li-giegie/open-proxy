// Package netutil 提供代理各模块共享的网络与配置工具：
//   - 连接工具：空闲超时双向拷贝（CopyStream）与写侧半关闭（CloseWrite），
//     socks5、httpproxy、relay 的透传阶段共用；
//   - TLS 配置构造：服务端/客户端两版入口——内容版（*FromPEM，给 PEM
//     字节，管理中心粘贴/上传走这里）与路径版（读文件后委托内容版，
//     CLI flag 走这里），命令行与管理中心共用同一套校验规则；
//   - 上游代理 URL 解析（UpstreamURL）；
//   - 测试 PKI（GenCA/GenLeaf）：测试用自签 CA 与叶子证书，供各包的
//     TLS/mTLS 测试共用。
package netutil

import (
	"net"
	"time"
)

// CopyStream 从 src 单向拷贝到 dst，每块数据写出后调用 onChunk 上报
// （nil 时跳过）。每次读写都把超时刷新到 idle 之后，长时间无数据流动
// 即超时断开，避免连接被慢速客户端永久占用。idle <= 0 时不设超时。
func CopyStream(dst, src net.Conn, idle time.Duration, onChunk func(int64)) {
	if onChunk == nil {
		onChunk = func(int64) {}
	}
	var buf = make([]byte, 32*1024)
	for {
		if idle > 0 {
			src.SetReadDeadline(time.Now().Add(idle))
		}
		n, err := src.Read(buf)
		if n > 0 {
			if idle > 0 {
				dst.SetWriteDeadline(time.Now().Add(idle))
			}
			if _, err = dst.Write(buf[:n]); err != nil {
				return
			}
			onChunk(int64(n))
		}
		if err != nil {
			// io.EOF 为对端正常结束，其余为连接错误或空闲超时
			return
		}
	}
}

// CloseWrite 半关闭连接的写侧（向对端发送 FIN），让另一个方向可以把
// 剩余数据传完。非 TCP 连接不支持半关闭时退化为整条关闭。
func CloseWrite(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	_ = c.Close()
}
