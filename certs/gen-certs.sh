#!/usr/bin/env bash
# 生成 open-proxy 代理链所需的一套证书（CA + 服务端 + 客户端）。
# 在 Git Bash 下运行；PowerShell/cmd 中把 -subj 的 "//" 改回 "/"。
#
# 修改 SAN（部署到新机器/域名）：编辑 server.ext 后重跑本脚本，
# 会用新 SAN 重新生成整套证书。

set -euo pipefail
cd "$(dirname "$0")"

# 关闭 Git Bash 的 MSYS 路径转换：-subj "/CN=..." 中的 /CN 才不会被
# 误转换成 C:/Programs/Git/CN=...（转换失败时 openssl 会生成 Subject
# 为空的证书，浏览器将报 NET::ERR_CERT_INVALID 且无法点击继续）
export MSYS_NO_PATHCONV=1

# 1) 自签 CA（10 年）
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -sha256 -key ca.key -days 3650 -subj "/CN=open-proxy-ca" -out ca.pem

# 2) 服务端证书（SAN 在 server.ext 中维护：客户端连什么地址，就写什么条目）
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=open-proxy-server" -out server.csr
openssl x509 -req -sha256 -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -out server.pem -extfile server.ext

# 3) 客户端证书（对上游/管理端 mTLS 时出示，扩展在 client.ext）
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -subj "/CN=open-proxy-client" -out client.csr
openssl x509 -req -sha256 -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -out client.pem -extfile client.ext

rm -f *.csr *.srl
openssl verify -CAfile ca.pem server.pem client.pem
echo "证书已生成：$(pwd)（SAN 见 server.ext）"

openssl pkcs12 -export -out client.pfx -inkey client.key -in client.pem -passout pass:123456
echo "浏览器mTLS客户端证书已生成 密码123456"
