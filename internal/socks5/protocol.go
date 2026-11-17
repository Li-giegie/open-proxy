// Package socks5 实现 SOCKS5 服务端（RFC 1928）：
//   - 认证协商支持无认证（0x00）与用户名/密码子协商（RFC 1929）；
//   - 代理命令只实现 CONNECT（TCP 代理），BIND 与 UDP ASSOCIATE 返回
//     COMMAND NOT SUPPORTED；
//   - 地址类型支持 IPv4、IPv6 与域名（由服务端代为解析）。
//
// 协议层的读写函数按阶段精确读取（先读定长头部、再按长度字段补读），
// 避免一次读走下一阶段的数据；ctx 取消时读取 goroutine 会随连接关闭退出。
package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Method 是客户端支持的认证方法编号（RFC 1928 §3）。
type Method uint8

const (
	// MethodNoAuth 无需认证，直接进入请求阶段。
	MethodNoAuth Method = iota
	// MethodUserPass 用户名/密码子协商（RFC 1929）。
	MethodUserPass Method = 2
	// MethodNoAcceptableMethods 服务端无法接受客户端提供的任何方法时，
	// 以此值回应并关闭连接。
	MethodNoAcceptableMethods Method = 255
)

func (m Method) String() string {
	switch {
	case m == MethodNoAuth:
		return "NoAuth"
	case m == MethodUserPass:
		return "UserPass"
	case m == MethodNoAcceptableMethods:
		return "NoAcceptableMethods"
	}
	return "Unassigned Method: " + strconv.Itoa(int(m))
}

// NewMethods 把原始方法编号列表转为 Method。
func NewMethods(methods []uint8) []Method {
	result := make([]Method, len(methods))
	for i := range methods {
		result[i] = Method(methods[i])
	}
	return result
}

// AuthRequest 是认证协商请求：VER(1) NMETHODS(1) METHODS(NMETHODS)。
type AuthRequest struct {
	Version  uint8
	NMethods uint8
	Methods  []Method
}

func (a *AuthRequest) String() string {
	return fmt.Sprintf("%d.%d.%v", a.Version, a.NMethods, a.Methods)
}

// ReadAuth 读取认证协商请求。buf 仅供复用，容量不足时内部另行分配。
func ReadAuth(ctx context.Context, r io.Reader, buf []byte) (*AuthRequest, error) {
	result := new(AuthRequest)
	if err := readWithContext(ctx, func() error {
		if len(buf) < 2 {
			buf = make([]byte, 2)
		}
		// 先读 VER 与 NMETHODS，再按 NMETHODS 精确补读，不会吞掉
		// 后续阶段的字节
		if _, err := io.ReadFull(r, buf[:2]); err != nil {
			return err
		}
		n := int(buf[1])
		result.Version = buf[0]
		result.NMethods = buf[1]
		if n > 0 {
			if len(buf) < 2+n {
				buf = make([]byte, 2+n)
			}
			if _, err := io.ReadFull(r, buf[2:2+n]); err != nil {
				return err
			}
			result.Methods = NewMethods(buf[2 : 2+n])
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// AuthResponse 是认证协商响应：VER(1) METHOD(1)。
type AuthResponse struct {
	Version uint8
	Methods Method
}

// Write 写出协商选定的方法。
func (r *AuthResponse) Write(w io.Writer, buf []byte) (int, error) {
	if len(buf) < 2 {
		return w.Write([]byte{r.Version, uint8(r.Methods)})
	}
	buf[0] = r.Version
	buf[1] = uint8(r.Methods)
	return w.Write(buf[:2])
}

// AddrType 是请求目标地址类型（ATYP）。
type AddrType uint8

const (
	AddrTypeIPV4       AddrType = 1
	AddrTypeIPV6       AddrType = 4
	AddrTypeDomainName AddrType = 3
)

func (a AddrType) String() string {
	switch a {
	case AddrTypeIPV4:
		return "IPv4"
	case AddrTypeIPV6:
		return "IPv6"
	case AddrTypeDomainName:
		return "DomainName"
	default:
		return "Unknown"
	}
}

// Command 是客户端请求的代理指令（CMD）。
type Command uint8

const (
	CommandConnect   Command = 1 + iota // TCP 代理
	CommandBind                         // 让 SOCKS 服务端开启监听 socket，等待目标服务器主动连代理（反向 TCP 连接）
	CommandAssociate                    // UDP 代理
)

func (c Command) String() string {
	switch c {
	case CommandConnect:
		return "Connect"
	case CommandBind:
		return "Bind"
	case CommandAssociate:
		return "Associate"
	default:
		return "Unknown"
	}
}

// Request 是代理请求：VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DST.PORT(2)。
type Request struct {
	Version  uint8    // 版本
	Command  Command  // 指令编号
	Reserved uint8    // 保留字段
	AddrType AddrType // 地址类型
	Addr     string   // IPv4、IPv6 的点分/冒分隔文本形式，或域名
	Port     uint16
}

func (r *Request) String() string {
	buffer := bytes.NewBuffer(make([]byte, 0, 128))
	fmt.Fprintf(buffer, "Version: %d, Cmd: %s, Reserved: %d, AddrType: %s, Addr: %s, Port: %d",
		r.Version, r.Command.String(), r.Reserved, r.AddrType.String(), r.Addr, r.Port)
	return buffer.String()
}

// ReadRequest 读取代理请求。IPv4/IPv6 的 DST.ADDR 解码为文本形式（如
// "127.0.0.1"），DomainName 解码为域名原文。buf 仅供复用。
func ReadRequest(ctx context.Context, r io.Reader, buf []byte) (*Request, error) {
	req := new(Request)
	if err := readWithContext(ctx, func() error {
		if len(buf) < 4 {
			buf = make([]byte, 4)
		}
		// 同 ReadAuth：先读 4 字节头部，ATYP 决定 DST.ADDR 的确切长度
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			return err
		}
		req.Version = buf[0]
		req.Command = Command(buf[1])
		req.Reserved = buf[2]
		req.AddrType = AddrType(buf[3])

		switch req.AddrType {
		case AddrTypeIPV4:
			addr, port, err := readAddrPort(r, buf, 4)
			if err != nil {
				return err
			}
			req.Addr = net.IP(addr).String()
			req.Port = port
		case AddrTypeIPV6:
			addr, port, err := readAddrPort(r, buf, 16)
			if err != nil {
				return err
			}
			req.Addr = net.IP(addr).String()
			req.Port = port
		case AddrTypeDomainName:
			// 1 字节域名长度 + 域名 + 2 字节端口
			if _, err := io.ReadFull(r, buf[:1]); err != nil {
				return err
			}
			n := int(buf[0])
			if n == 0 {
				return errors.New("request: empty domain name")
			}
			if len(buf) < n+2 {
				buf = make([]byte, n+2)
			}
			if _, err := io.ReadFull(r, buf[:n+2]); err != nil {
				return err
			}
			req.Addr = string(buf[:n])
			req.Port = binary.BigEndian.Uint16(buf[n : n+2])
		default:
			return fmt.Errorf("request: unknown address type: %v", req.AddrType)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return req, nil
}

// readAddrPort 读取 IP 字节串（addrLen 字节）与 2 字节端口。
func readAddrPort(r io.Reader, buf []byte, addrLen int) (addr []byte, port uint16, err error) {
	if len(buf) < addrLen+2 {
		buf = make([]byte, addrLen+2)
	}
	if _, err = io.ReadFull(r, buf[:addrLen+2]); err != nil {
		return nil, 0, err
	}
	// 复制出来：buf 会被复用
	out := make([]byte, addrLen)
	copy(out, buf[:addrLen])
	return out, binary.BigEndian.Uint16(buf[addrLen : addrLen+2]), nil
}

// UserPassRequest 是 RFC 1929 用户名/密码子协商请求：
// VER(1) ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)。
type UserPassRequest struct {
	Version  uint8
	Username string
	Password string
}

func (r *UserPassRequest) String() string {
	return fmt.Sprintf("Version: %d, Username: %s, Password: %s", r.Version, r.Username, r.Password)
}

// ReadUserPassRequest 读取用户名/密码子协商请求。buf 仅供复用。
func ReadUserPassRequest(ctx context.Context, r io.Reader, buf []byte) (*UserPassRequest, error) {
	req := new(UserPassRequest)
	if err := readWithContext(ctx, func() error {
		if len(buf) < 2 {
			buf = make([]byte, 2)
		}
		// 子协商版本号固定为 1（RFC 1929），与 SOCKS 版本 5 无关
		if _, err := io.ReadFull(r, buf[:2]); err != nil {
			return err
		}
		req.Version = buf[0]
		if n := int(buf[1]); n > 0 {
			if len(buf) < n {
				buf = make([]byte, n)
			}
			if _, err := io.ReadFull(r, buf[:n]); err != nil {
				return err
			}
			req.Username = string(buf[:n])
		}
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return err
		}
		if n := int(buf[0]); n > 0 {
			if len(buf) < n {
				buf = make([]byte, n)
			}
			if _, err := io.ReadFull(r, buf[:n]); err != nil {
				return err
			}
			req.Password = string(buf[:n])
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return req, nil
}

// UserPassResponseStatus 是子协商结果状态。
type UserPassResponseStatus uint8

const (
	UserPassResponseStatusSuccess UserPassResponseStatus = iota
	UserPassResponseStatusFail
)

// UserPassResponse 是子协商响应：VER(1) STATUS(1)。
type UserPassResponse struct {
	Version uint8
	Status  UserPassResponseStatus
}

func (r *UserPassResponse) Write(w io.Writer, buf []byte) (int, error) {
	if len(buf) < 2 {
		buf = make([]byte, 2)
	}
	buf[0] = r.Version
	buf[1] = uint8(r.Status)
	return w.Write(buf[:2])
}

// Reply 是请求处理结果的回复码（REP）。
type Reply uint8

const (
	ReplySucceeded               Reply = iota // 正常，后续开始转发
	ReplyGeneralServerFailure                 // 服务内部异常、未知错误
	ReplyConnectionNotAllowed                 // 访问被策略 / ACL 拦截（黑白名单）
	ReplyNetworkUnreachable                   // 网络不可达 路由层面，目标网段不通
	ReplyHostUnreachable                      // 主机不存在、DNS 解析失败 / 无路由到主机
	ReplyConnectionRefused                    // 目标端口没监听，对方主动拒绝 TCP
	ReplyTTLExpired                           // RFC 本意是 TTL 耗尽；工程上大家一般用来表示连接超时
	ReplyCommandNotSupported                  // CMD 不是 0x01/0x02/0x03，比如收到未知 CMD
	ReplyAddressTypeNotSupported              // ATYP 不是 0x01 (ipv4)、0x03 (域名)、0x04 (ipv6)
)

func (r Reply) String() string {
	switch r {
	case ReplySucceeded:
		return "SUCCEEDED"
	case ReplyGeneralServerFailure:
		return "GENERAL_SERVER_FAILURE"
	case ReplyConnectionNotAllowed:
		return "CONNECTION_NOT_ALLOWED"
	case ReplyNetworkUnreachable:
		return "NETWORK_UNREACHABLE"
	case ReplyHostUnreachable:
		return "HOST_UNREACHABLE"
	case ReplyConnectionRefused:
		return "CONNECTION_REFUSED"
	case ReplyTTLExpired:
		return "TTL_EXPIRED"
	case ReplyCommandNotSupported:
		return "COMMAND_NOT_SUPPORTED"
	case ReplyAddressTypeNotSupported:
		return "ADDRESS_TYPE_NOT_SUPPORTED"
	default:
		return "UNKNOWN_REPLY"
	}
}

// Response 是代理请求响应：VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR BND.PORT(2)。
type Response struct {
	Version  uint8
	Reply    Reply
	Reserved uint8 // 保留字段
	AddrType AddrType
	Addr     string
	Port     uint16
}

func (r *Response) String() string {
	buffer := bytes.NewBuffer(make([]byte, 0, 128))
	fmt.Fprintf(buffer, "Version: %d, Reply: %s, Reserved: %d, AddrType: %s, Addr: %s, Port: %d",
		r.Version, r.Reply.String(), r.Reserved, r.AddrType.String(), r.Addr, r.Port)
	return buffer.String()
}

// Write 按 ATYP 编码 BND.ADDR 写出响应：IPv4 为 4 字节、IPv6 为 16 字节、
// 域名为 1 字节长度前缀 + 内容，端口 2 字节大端附后。Addr 为空时按
// 0.0.0.0:0 编码（客户端通常忽略响应里的 BND.ADDR）。
func (r *Response) Write(w io.Writer, buf []byte) (int, error) {
	addrType := r.AddrType
	var addr []byte
	switch addrType {
	case AddrTypeIPV4, AddrTypeIPV6:
		ip := net.ParseIP(r.Addr)
		if ip == nil {
			return 0, fmt.Errorf("response: invalid %s addr %q", addrType, r.Addr)
		}
		if addrType == AddrTypeIPV4 {
			addr = ip.To4()
			if addr == nil {
				return 0, fmt.Errorf("response: %q is not an IPv4 address", r.Addr)
			}
		} else {
			addr = ip.To16()
			if addr == nil {
				return 0, fmt.Errorf("response: %q is not an IPv6 address", r.Addr)
			}
		}
	case AddrTypeDomainName:
		if len(r.Addr) > 255 {
			return 0, fmt.Errorf("response: domain name too long: %d", len(r.Addr))
		}
		addr = make([]byte, len(r.Addr)+1)
		addr[0] = uint8(len(r.Addr))
		copy(addr[1:], r.Addr)
	default:
		// 未指定 ATYP（零值）：按字面形式推断，空地址按 0.0.0.0 编码
		switch ip := net.ParseIP(r.Addr); {
		case ip != nil && ip.To4() != nil:
			addrType, addr = AddrTypeIPV4, ip.To4()
		case ip != nil:
			addrType, addr = AddrTypeIPV6, ip.To16()
		case r.Addr != "":
			addrType = AddrTypeDomainName
			addr = make([]byte, len(r.Addr)+1)
			addr[0] = uint8(len(r.Addr))
			copy(addr[1:], r.Addr)
		default:
			// net.IPv4zero 是 16 字节的 v4-in-v6 形式，必须 To4 取 4 字节
			addrType, addr = AddrTypeIPV4, net.IPv4zero.To4()
		}
	}

	n := 6 + len(addr)
	if len(buf) < n {
		buf = make([]byte, n)
	}
	buf[0] = r.Version
	buf[1] = uint8(r.Reply)
	buf[2] = r.Reserved
	buf[3] = uint8(addrType)
	copy(buf[4:], addr)
	binary.BigEndian.PutUint16(buf[n-2:], r.Port)
	return w.Write(buf[:n])
}

// readWithContext 在 goroutine 中执行 read 并允许 ctx 取消先行返回。
// 注意：ctx 取消后读取 goroutine 仍会阻塞在 r 上，直到连接被关闭才退出，
// 因此调用方在取消后应尽快关闭底层连接。
func readWithContext(ctx context.Context, read func() error) error {
	done := make(chan error, 1)
	go func() {
		done <- read()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
