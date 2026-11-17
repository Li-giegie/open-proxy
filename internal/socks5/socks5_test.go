package socks5

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Li-giegie/open-proxy/internal/netutil"
)

// ---------- 协议层单元测试 ----------

func TestReadAuth(t *testing.T) {
	// 正常协商：VER=5，两个方法
	r := bytes.NewReader([]byte{5, 2, 0, 2})
	auth, err := ReadAuth(context.Background(), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Version != 5 || auth.NMethods != 2 ||
		len(auth.Methods) != 2 || auth.Methods[0] != MethodNoAuth || auth.Methods[1] != MethodUserPass {
		t.Errorf("auth = %s", auth.String())
	}

	// NMETHODS=0：方法列表为空，协议层放行（由服务层决定如何回应）
	auth, err = ReadAuth(context.Background(), bytes.NewReader([]byte{5, 0}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth.Version != 5 || len(auth.Methods) != 0 {
		t.Errorf("auth = %s", auth.String())
	}

	// 声明 2 个方法但只给了 1 个字节：截断报错
	if _, err := ReadAuth(context.Background(), bytes.NewReader([]byte{5, 2, 0}), nil); err == nil {
		t.Errorf("truncated methods: want error")
	}
}

// TestReadAuthContextCanceled 验证 ctx 取消先行返回。
func TestReadAuthContextCanceled(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := ReadAuth(ctx, server, nil); err == nil {
		t.Errorf("want context deadline error")
	}
}

func TestAuthResponseWrite(t *testing.T) {
	var buf bytes.Buffer
	resp := &AuthResponse{Version: 5, Methods: MethodUserPass}
	if _, err := resp.Write(&buf, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{5, byte(MethodUserPass)}) {
		t.Errorf("bytes = %v, want [5 2]", buf.Bytes())
	}
}

func TestReadRequest(t *testing.T) {
	// IPv4：127.0.0.1:80
	raw := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}
	req, err := ReadRequest(context.Background(), bytes.NewReader(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Version != 5 || req.Command != CommandConnect || req.AddrType != AddrTypeIPV4 ||
		req.Addr != "127.0.0.1" || req.Port != 80 {
		t.Errorf("req = %s", req.String())
	}

	// IPv6：::1:443（16 字节地址，前 15 个 0）
	raw = append([]byte{5, 1, 0, 4}, make([]byte, 15)...)
	raw = append(raw, 1, 0x01, 0xbb)
	req, err = ReadRequest(context.Background(), bytes.NewReader(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.AddrType != AddrTypeIPV6 || req.Addr != "::1" || req.Port != 443 {
		t.Errorf("req = %s", req.String())
	}

	// 域名：localhost:8080
	raw = []byte{5, 1, 0, 3, 9}
	raw = append(raw, "localhost"...)
	raw = append(raw, 0x1f, 0x90)
	req, err = ReadRequest(context.Background(), bytes.NewReader(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.AddrType != AddrTypeDomainName || req.Addr != "localhost" || req.Port != 8080 {
		t.Errorf("req = %s", req.String())
	}

	// 未知 ATYP：报错
	if _, err := ReadRequest(context.Background(), bytes.NewReader([]byte{5, 1, 0, 5}), nil); err == nil {
		t.Errorf("unknown atyp: want error")
	}
}

func TestReadUserPassRequest(t *testing.T) {
	raw := []byte{1, 5}
	raw = append(raw, "alice"...)
	raw = append(raw, 4)
	raw = append(raw, "pass"...)

	req, err := ReadUserPassRequest(context.Background(), bytes.NewReader(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Version != 1 || req.Username != "alice" || req.Password != "pass" {
		t.Errorf("req = %s", req.String())
	}

	// 截断：密码声明 4 字节但只给 2 个
	raw = []byte{1, 0, 4}
	raw = append(raw, "pw"...)
	if _, err := ReadUserPassRequest(context.Background(), bytes.NewReader(raw), nil); err == nil {
		t.Errorf("truncated password: want error")
	}
}

// TestResponseWrite 对三种 ATYP 与空地址做字节级断言。
func TestResponseWrite(t *testing.T) {
	cases := []struct {
		name string
		resp Response
		want []byte
	}{
		{
			"ipv4",
			Response{Version: 5, Reply: ReplySucceeded, AddrType: AddrTypeIPV4, Addr: "127.0.0.1", Port: 1080},
			append([]byte{5, 0, 0, 1, 127, 0, 0, 1}, 0x04, 0x38),
		},
		{
			"ipv6",
			Response{Version: 5, Reply: ReplyConnectionRefused, AddrType: AddrTypeIPV6, Addr: "::1", Port: 80},
			// ::1 编码为 16 字节（15 个 0 + 1），在子测试里单独构造比对
			nil,
		},
		{
			"domain",
			Response{Version: 5, Reply: ReplyCommandNotSupported, AddrType: AddrTypeDomainName, Addr: "a.b", Port: 443},
			[]byte{5, 7, 0, 3, 3, 'a', '.', 'b', 0x01, 0xbb},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := c.resp.Write(&buf, nil); err != nil {
				t.Fatal(err)
			}
			if c.name == "ipv6" {
				want := append([]byte{5, 5, 0, 4}, make([]byte, 15)...)
				want = append(want, 1, 0x00, 0x50) // ::1 + 80
				if !bytes.Equal(buf.Bytes(), want) {
					t.Errorf("bytes = %v, want %v", buf.Bytes(), want)
				}
				return
			}
			if !bytes.Equal(buf.Bytes(), c.want) {
				t.Errorf("bytes = %v, want %v", buf.Bytes(), c.want)
			}
		})
	}

	// 空地址：按 0.0.0.0:0 编码
	var buf bytes.Buffer
	if _, err := (&Response{Version: 5, Reply: ReplyHostUnreachable}).Write(&buf, nil); err != nil {
		t.Fatal(err)
	}
	want := []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("empty addr bytes = %v, want %v", buf.Bytes(), want)
	}
}

// ---------- 端到端测试 ----------

// startSocksServer 启动一个 SOCKS5 代理并返回其监听地址；
// tlsConf 非空时以 TLS（或 mTLS）监听。
func startSocksServer(t *testing.T, opts Options, tlsConf *tls.Config) string {
	t.Helper()
	proxy, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsConf != nil {
		ln = tls.NewListener(ln, tlsConf)
	}
	go func() { _ = proxy.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// startEcho 启动一个原样回显的 TCP 服务并返回其地址。
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// socksDial 极简 SOCKS5 客户端：拨号代理后完成认证协商（按需子协商）与
// CONNECT，返回建立好的连接与响应回复码。atyp 指定目标地址类型。
func socksDial(t *testing.T, proxyAddr, user, password, target string, atyp AddrType, cmd Command) (net.Conn, Reply) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	return socksHandshake(t, conn, user, password, target, atyp, cmd)
}

// socksHandshake 在已建立的连接（明文或 TLS）上完成 SOCKS5 握手与 CONNECT。
func socksHandshake(t *testing.T, conn net.Conn, user, password, target string, atyp AddrType, cmd Command) (net.Conn, Reply) {
	t.Helper()

	// 认证协商：有凭证时提供 UserPass，否则只提供 NoAuth
	var methods []byte
	if user != "" {
		methods = []byte{0, 2}
	} else {
		methods = []byte{0}
	}
	hello := append([]byte{5, byte(len(methods))}, methods...)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[0] != 5 {
		t.Fatalf("auth version = %d, want 5", head[0])
	}
	if method := Reply(head[1]); method == Reply(MethodNoAcceptableMethods) {
		return conn, Reply(method)
	}

	// 用户名/密码子协商
	if head[1] == byte(MethodUserPass) {
		up := []byte{1, byte(len(user))}
		up = append(up, user...)
		up = append(up, byte(len(password)))
		up = append(up, password...)
		if _, err := conn.Write(up); err != nil {
			t.Fatal(err)
		}
		status := make([]byte, 2)
		if _, err := io.ReadFull(conn, status); err != nil {
			t.Fatal(err)
		}
		if status[1] != byte(UserPassResponseStatusSuccess) {
			return conn, Reply(status[1])
		}
	}

	// CONNECT 请求：按 atyp 编码目标地址
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}
	req := []byte{5, byte(cmd), 0, byte(atyp)}
	switch atyp {
	case AddrTypeIPV4, AddrTypeIPV6:
		ip := net.ParseIP(host)
		if ip == nil {
			t.Fatalf("invalid ip %q", host)
		}
		if atyp == AddrTypeIPV4 {
			req = append(req, ip.To4()...)
		} else {
			req = append(req, ip.To16()...)
		}
	case AddrTypeDomainName:
		if len(host) > 255 {
			t.Fatalf("domain too long: %q", host)
		}
		req = append(req, byte(len(host)))
		req = append(req, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	req = append(req, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	// 读响应：VER REP RSV ATYP + 变长地址 + 端口
	respHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHead); err != nil {
		t.Fatal(err)
	}
	switch atypOfResp := AddrType(respHead[3]); atypOfResp {
	case AddrTypeIPV4:
		_, _ = io.CopyN(io.Discard, conn, 4+2)
	case AddrTypeIPV6:
		_, _ = io.CopyN(io.Discard, conn, 16+2)
	case AddrTypeDomainName:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			t.Fatal(err)
		}
		_, _ = io.CopyN(io.Discard, conn, int64(lenByte[0])+2)
	default:
		t.Fatalf("response atyp = %v", atypOfResp)
	}
	return conn, Reply(respHead[1])
}

// TestConnectIPv4 验证 IPv4 目标的 CONNECT 全链路：经代理双向透传。
func TestConnectIPv4(t *testing.T) {
	echoAddr := startEcho(t)
	proxyAddr := startSocksServer(t, Options{}, nil)

	conn, reply := socksDial(t, proxyAddr, "", "", echoAddr, AddrTypeIPV4, CommandConnect)
	defer conn.Close()
	if reply != ReplySucceeded {
		t.Fatalf("reply = %v, want SUCCEEDED", reply)
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Errorf("echo = %q, want %q", buf, "hello")
	}
}

// TestConnectDomain 验证域名目标的 CONNECT：由代理代为解析。
func TestConnectDomain(t *testing.T) {
	_, portStr, _ := net.SplitHostPort(startEcho(t))
	proxyAddr := startSocksServer(t, Options{}, nil)

	conn, reply := socksDial(t, proxyAddr, "", "",
		net.JoinHostPort("localhost", portStr), AddrTypeDomainName, CommandConnect)
	defer conn.Close()
	if reply != ReplySucceeded {
		t.Fatalf("reply = %v, want SUCCEEDED", reply)
	}

	if _, err := conn.Write([]byte("domain-ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("domain-ok"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "domain-ok" {
		t.Errorf("echo = %q, want %q", buf, "domain-ok")
	}
}

// TestAuthRequired 验证启用认证后：正确凭证放行、错误凭证被拒。
func TestAuthRequired(t *testing.T) {
	echoAddr := startEcho(t)
	proxyAddr := startSocksServer(t, Options{
		Authenticator: &Credentials{Username: "alice", Password: "s3cret"},
	}, nil)

	// 正确凭证
	conn, reply := socksDial(t, proxyAddr, "alice", "s3cret", echoAddr, AddrTypeIPV4, CommandConnect)
	if reply != ReplySucceeded {
		t.Fatalf("reply = %v, want SUCCEEDED", reply)
	}
	if _, err := conn.Write([]byte("mtls")); err != nil { // 复用连接做一次透传验证
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "mtls" {
		t.Errorf("echo = %q, want %q", buf, "mtls")
	}
	conn.Close()

	// 错误密码：子协商失败后服务端关闭连接
	conn, reply = socksDial(t, proxyAddr, "alice", "wrong", echoAddr, AddrTypeIPV4, CommandConnect)
	defer conn.Close()
	if reply != Reply(UserPassResponseStatusFail) {
		t.Fatalf("reply = %v, want userpass fail", reply)
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		// 写入可能因缓冲而成功，但读取必然 EOF
		if _, err = conn.Read(buf); err == nil {
			t.Errorf("connection should be closed after auth failure")
		}
	}
}

// TestNoAcceptableMethods 验证启用认证后客户端只提供无认证方法时，
// 服务端回应 0xFF 并关闭连接。
func TestNoAcceptableMethods(t *testing.T) {
	proxyAddr := startSocksServer(t, Options{
		Authenticator: &Credentials{Username: "u", Password: "p"},
	}, nil)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[0] != 5 || Method(head[1]) != MethodNoAcceptableMethods {
		t.Errorf("reply = %v, want NoAcceptableMethods", Method(head[1]))
	}
}

// TestUnsupportedCommand 验证 BIND / UDP ASSOCIATE 回应 COMMAND NOT SUPPORTED。
func TestUnsupportedCommand(t *testing.T) {
	echoAddr := startEcho(t)
	proxyAddr := startSocksServer(t, Options{}, nil)

	for _, cmd := range []Command{CommandBind, CommandAssociate} {
		conn, reply := socksDial(t, proxyAddr, "", "", echoAddr, AddrTypeIPV4, cmd)
		conn.Close()
		if reply != ReplyCommandNotSupported {
			t.Errorf("cmd %v: reply = %v, want COMMAND_NOT_SUPPORTED", cmd, reply)
		}
	}
}

// TestConnectRefused 验证目标端口无监听时回应 CONNECTION_REFUSED。
func TestConnectRefused(t *testing.T) {
	// 找一个确定无监听的端口：先监听再立刻关闭
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedAddr := ln.Addr().String()
	ln.Close()

	proxyAddr := startSocksServer(t, Options{}, nil)
	conn, reply := socksDial(t, proxyAddr, "", "", refusedAddr, AddrTypeIPV4, CommandConnect)
	defer conn.Close()
	if reply != ReplyConnectionRefused {
		t.Errorf("reply = %v, want CONNECTION_REFUSED", reply)
	}
}

// TestTLSSocks5 验证 TLS 监听：客户端以 TLS 接入后走完整 SOCKS5 流程，
// 隧道内数据双向透传。
func TestTLSSocks5(t *testing.T) {
	echoAddr := startEcho(t)

	caPEM, ca, caKey := netutil.GenCA(t)
	srvCertPEM, srvKeyPEM := netutil.GenLeaf(t, ca, caKey, "socks-proxy", true)
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := startSocksServer(t, Options{}, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		MinVersion:   tls.VersionTLS12,
	})

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	if _, reply := socksHandshake(t, conn, "", "", echoAddr, AddrTypeIPV4, CommandConnect); reply != ReplySucceeded {
		t.Fatalf("reply = %v, want SUCCEEDED", reply)
	}
	if _, err := conn.Write([]byte("tls-socks")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("tls-socks"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "tls-socks" {
		t.Errorf("echo = %q, want %q", buf, "tls-socks")
	}
}

// TestMTLSSocks5 验证 mTLS 监听：客户端出示证书后放行，不出示则 TLS
// 握手被拒（到不了 SOCKS5 阶段）。
func TestMTLSSocks5(t *testing.T) {
	echoAddr := startEcho(t)

	caPEM, ca, caKey := netutil.GenCA(t)
	srvCertPEM, srvKeyPEM := netutil.GenLeaf(t, ca, caKey, "socks-proxy", true)
	cliCertPEM, cliKeyPEM := netutil.GenLeaf(t, ca, caKey, "socks-client", false)
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, err := tls.X509KeyPair(cliCertPEM, cliKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caPEM)
	proxyAddr := startSocksServer(t, Options{}, &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	})

	// 带客户端证书：握手成功，SOCKS5 流程与透传正常
	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{cliCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("mtls dial: %v", err)
	}
	defer conn.Close()
	if _, reply := socksHandshake(t, conn, "", "", echoAddr, AddrTypeIPV4, CommandConnect); reply != ReplySucceeded {
		t.Fatalf("reply = %v, want SUCCEEDED", reply)
	}
	if _, err := conn.Write([]byte("mtls-socks")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("mtls-socks"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "mtls-socks" {
		t.Errorf("echo = %q, want %q", buf, "mtls-socks")
	}

	// 不带客户端证书：被拒。TLS 1.3 下客户端握手可能在服务端校验证书
	// 前就完成，拒绝要等到首次读写才暴露
	noCert, err := tls.Dial("tcp", proxyAddr, &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12})
	if err != nil {
		return
	}
	defer noCert.Close()
	if _, err := noCert.Write([]byte{5, 1, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(noCert, make([]byte, 2)); err == nil {
		t.Errorf("without client cert: connection should be rejected")
	}
}

// TestProxyClose 验证 Close 断开监听与活动连接（含 CONNECT 隧道），
// Serve 随之返回。
func TestProxyClose(t *testing.T) {
	echoAddr := startEcho(t)

	proxy, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- proxy.Serve(ln) }()

	// 建立一条 CONNECT 隧道（长连接）
	conn, reply := socksDial(t, ln.Addr().String(), "", "", echoAddr, AddrTypeIPV4, CommandConnect)
	if reply != ReplySucceeded {
		t.Fatalf("reply = %v, want SUCCEEDED", reply)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}

	// Close：监听与隧道都断开
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := proxy.Close(); err != nil { // 幂等
		t.Fatal(err)
	}

	// 隧道被断
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(buf); err == nil {
		t.Errorf("tunnel should be closed")
	}

	// Serve 返回 nil
	select {
	case err := <-serveDone:
		if err != nil {
			t.Errorf("serve = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("serve did not return after Close")
	}

	// 监听已关：新连接被拒
	if _, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		t.Errorf("new conn should be refused after Close")
	}
}
