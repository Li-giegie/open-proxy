# open-proxy

正向代理（HTTP/HTTPS、SOCKS5）、反向代理、裸 TCP 中继与代理资源管理
中心，单二进制、零运行时依赖，内置证书工具。

```
open-proxy forward   # HTTP/HTTPS 正向代理：认证、代理链（上游代理）、TLS/mTLS
open-proxy reverse   # HTTP 反向代理：多 backend 负载均衡、TLS/mTLS
open-proxy socks5    # SOCKS5 代理（CONNECT）：用户名/密码认证、TLS/mTLS
open-proxy relay     # TCP 中继：多上游加权 + failover、双向 TLS/mTLS
open-proxy admin     # 管理中心：Web UI + REST API，统一管理各类资源
open-proxy certgen   # 证书工具：生成/签发证书（ECDSA / RSA / Ed25519）
```

所有服务子命令均支持**命令行参数**与 **JSON 配置文件**（`-c/--config`）
两种启动方式，两者二选一、不可混用（混用直接报错）。

- [构建安装](#构建安装)
- [配置文件启动](#配置文件启动)
- [证书生成](#证书生成)
- [TLS 与 mTLS 约定](#tls-与-mtls-约定)
- [正向代理 forward](#正向代理-forward)
- [代理链（正向代理级联）](#代理链正向代理级联)
- [反向代理 reverse](#反向代理-reverse)
- [SOCKS5 代理 socks5](#socks5-代理-socks5)
- [TCP 中继 relay](#tcp-中继-relay)
- [管理中心 admin](#管理中心-admin)
- [REST API 参考](#rest-api-参考)
- [架构](#架构)
- [常见问题](#常见问题)

## 构建安装

要求 Go 1.22+（依赖 `net/http` 的方法路由模式匹配）。

```bash
go build -o open-proxy .
```

## 配置文件启动

五个服务子命令与 certgen 都支持 `-c/--config` 指向 JSON 配置文件，
**键名与命令行 flag 完全一致**，文件里没写的字段落回 flag 默认值：

```bash
open-proxy forward -c configs/forward.example.json
open-proxy reverse -c configs/reverse.example.json
open-proxy socks5  -c configs/socks5.example.json
open-proxy relay   -c configs/relay.example.json
open-proxy admin   -c configs/admin.example.json
```

`configs/` 下每种命令都有一份带全部字段的示例。relay 的配置文件为
结构化格式（支持多上游、每上游独立 TLS），见
[relay](#tcp-中继-relay) 一节。

**二选一语义**：给了 `--config` 再显式传任何其他 flag 会直接报错
（`配置文件与命令行参数二选一：同时给出了 --xxx`），不存在"谁覆盖谁"
的歧义——只用配置文件时缺失字段用默认值，只用命令行时与原有行为
完全一致。

## 证书生成

### 内置 certgen 命令（推荐）

两种模式，输出到 `--out`（默认 `certs`，已存在同名文件时拒绝覆盖）：

```bash
# 生成模式：自签 CA + 服务端证书，输出 ca.pem / ca-key.pem / cert.pem / key.pem
open-proxy certgen --cn 127.0.0.1 --days 3650 -o certs

# 签发模式：由已有 CA 签发叶子证书，输出 cert.pem / key.pem
# 客户端证书（mTLS 出示，CN 即身份）：
open-proxy certgen --ca certs/ca.pem --ca-key certs/ca-key.pem \
    --usage client --cn alice -o certs/alice
# 服务端证书（SAN 覆盖 CN 外加 localhost、127.0.0.1、::1）：
open-proxy certgen --ca certs/ca.pem --ca-key certs/ca-key.pem \
    --cn node2.example.com -o certs/node2
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--cn` | `open-proxy` | 叶子证书 CN：服务端形态为域名/IP（写入 SAN），客户端形态为身份名 |
| `--days` | 3650 | 叶子证书有效期天数 |
| `--org` | 空 | 主题 Organization（可重复） |
| `--dns` / `--ip` | 空 | 附加 DNS / IP SAN（可重复，服务端形态生效） |
| `--usage` | server | 叶子用途：server / client（mTLS 身份，仅 ClientAuth）/ both |
| `--algorithm` | ECDSA | 签名算法：ECDSA / RSA / Ed25519（叶子跟随 CA 算法） |
| `--curve` | P-256 | ECDSA 曲线：P-256 / P-384 / P-521 |
| `--rsa-bits` | 2048 | RSA 位数（算法为 RSA 时，至少 2048） |
| `--ca-cn` / `--ca-days` | `open-proxy-ca` / 3650 | CA 参数（生成模式） |
| `--ca` / `--ca-key` | 空 | 签发模式：已有 CA 的证书与私钥文件（必须成对） |
| `--pfx-pass` | 不导出 | 额外导出 `cert.pfx`（PKCS#12，仅叶子证书+私钥，与 openssl `pkcs12 -export` 默认一致，浏览器/系统双击导入），值为导入口令；显式给空值则导出无口令的 pfx |
| `--pfx-chain` | 关 | PFX 一并包含 CA 证书（对应 openssl `-certfile`；浏览器导入客户端证书不需要，且会把 CA 装进导入方的信任库） |

叶子证书私钥以 PKCS#8 PEM 输出；读取兼容 PKCS#8 / EC SEC1 / RSA PKCS#1
（旧证书可继续用于签发模式）。**CA 私钥（ca-key.pem）妥善保管**，
持有它即可继续签发任意客户端/服务端证书；SAN 白名单语义——多写不
报错，少写必校验失败（Go 1.15+ 只看 SAN，CN 无效）。

### certs/ 脚本（备用）

`certs/gen-certs.sh`（Git Bash）一键生成整套测试证书，扩展配置在
`server.ext` / `client.ext` 中可编辑。certgen 命令是其替代品，能力
是它的超集。

## TLS 与 mTLS 约定

三个概念在本文中反复出现：

| 层级 | 谁验证谁 | 涉及参数 |
|---|---|---|
| 明文 | 无 | 不配任何证书 |
| TLS（单向） | 客户端验证服务端 | 服务端 `--cert/--key`；客户端配对端 CA |
| mTLS（双向） | 双向验证 | TLS 基础上，服务端 `--client-ca` + 客户端出示证书 |

## 正向代理 forward

客户端（浏览器/curl/程序）把 open-proxy 配置为 HTTP 代理；HTTPS 目标走
CONNECT 隧道（端到端加密，代理不可见内容），HTTP 目标以绝对 URI 转发。

### 场景 1：本机开放代理

```bash
open-proxy.exe forward -a 127.0.0.1:1080
```

```bash
curl -x http://127.0.0.1:1080 http://httpbin.org/get      # HTTP 转发
curl -x http://127.0.0.1:1080 https://httpbin.org/get     # CONNECT 隧道
```

### 场景 2：带 Basic 认证（防陌生人使用）

```bash
open-proxy.exe forward -a 0.0.0.0:1080 --user alice --password s3cret
```

```bash
curl -x http://alice:s3cret@host:1080 https://example.com/
# 无凭证/错误凭证 → 407 Proxy Authentication Required
```

### 场景 3：TLS 监听（凭证不落明文）

```bash
open-proxy.exe forward -a 0.0.0.0:1080 \
    --cert certs/server.pem --key certs/server.key \
    --user alice --password s3cret
```

客户端用 `https://` 形式的代理地址：`curl -x https://host:1080 ...`。
注意**多数浏览器代理设置不支持 https:// 形式的代理**（见[常见问题](#常见问题)），
浏览器场景一般保持明文监听（本机回环）+ 认证即可。

### 场景 4：mTLS 监听（只放持证客户端）

```bash
open-proxy.exe forward -a 0.0.0.0:1080 \
    --cert certs/server.pem --key certs/server.key \
    --client-ca certs/ca.pem
```

客户端需出示 `client.pem`（curl：`--cert certs/client.pem --key certs/client.key`）。

### 全部参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-a, --address` | `:1080` | 监听地址 |
| `--user` / `--password` | 空 | 面向客户端的 Basic 认证（必须成对） |
| `--cert` / `--key` | 空 | 监听端 TLS（必须成对） |
| `--client-ca` | 空 | 监听端 mTLS（依赖 cert/key） |
| `--upstream` | 空 | 上游正向代理，启用代理链（见下节） |
| `--upstream-user` / `--upstream-password` | 空 | 对上游的 Basic 认证 |
| `--upstream-ca` | 空 | 校验 https 上游的证书（CA PEM 文件路径） |
| `--upstream-cert` / `--upstream-key` | 空 | 对上游 mTLS 出示的客户端证书 |
| `--dial-timeout` | 10s | 连接上游（含 TLS 握手/CONNECT 响应）超时 |
| `--idle-timeout` | 2m | CONNECT 隧道空闲超时 |
| `-c, --config` | 空 | JSON 配置文件（与命令行参数二选一） |

行为说明：`X-Forwarded-For` 逐跳追加；3xx 重定向原样透传（客户端自行
跟随）；逐跳头（`Connection`、`Proxy-Authorization` 等）按 RFC 9110 剔除。

## 代理链（正向代理级联）

本机代理的**所有出站流量**先经上游代理 B 转发，形成"代理链"。目的地仍由
客户端请求决定，两跳认证相互独立：

```
客户端 ──▶ 本地代理 A ──▶ 上游代理 B ──▶ 目标
   （可选认证）  （A 对 B 的认证）
```

```bash
# 上游代理 B：开放或带认证
open-proxy.exe forward -a 10.0.0.2:1080 --user up --password b-pass

# 本地代理 A：出站全部经 B
open-proxy.exe forward -a 127.0.0.1:1081 \
    --upstream http://up:b-pass@10.0.0.2:1080
```

- 普通 HTTP：A 向 B 发 CONNECT 建隧道后转发（B 看不到明文差异，目标不变）；
- HTTPS：双层嵌套隧道，TLS 仍是客户端 ⇄ 目标端到端，A、B 都不可见内容；
- 认证三层独立：客户端对 A、A 对 B（`--upstream-user/--upstream-password`
  或 URL userinfo，二者不可同时使用）、B 的拒绝对客户端表现为 502。

**上游为 https（TLS/mTLS）**：

```bash
open-proxy.exe forward -a 127.0.0.1:1081 \
    --upstream https://10.0.0.2:1080 \
    --upstream-user up --upstream-password b-pass \
    --upstream-ca certs/ca.pem \
    --upstream-cert certs/client.pem --upstream-key certs/client.key
```

`--upstream-ca` 是**必配**的（自签上游），没有"跳过校验"选项——链上代理
掌握全部流量，跳过校验等于请中间人进门。B 用公共可信证书（如 Let's
Encrypt + 真实域名）时可不配。

## 反向代理 reverse

标准语义：客户端直接访问代理地址，请求被转发到固定的 backend 列表
（多个时轮询负载均衡），保留客户端原始 Host 头（便于后端按域名路由），
附加 `X-Forwarded-For/Host/Proto`。

### 场景 1：单 backend / 负载均衡

```bash
open-proxy.exe reverse -a :80 \
    --backend http://127.0.0.1:9000 \
    --backend http://127.0.0.1:9001
```

### 场景 2：监听 TLS / mTLS

```bash
open-proxy.exe reverse -a :443 \
    --backend http://127.0.0.1:9000 \
    --cert certs/server.pem --key certs/server.key \
    --client-ca certs/ca.pem
```

### 场景 3：对 https backend（TLS/mTLS）

```bash
open-proxy.exe reverse -a :80 \
    --backend https://internal.example.com \
    --backend-ca certs/ca.pem \
    --backend-cert certs/client.pem --backend-key certs/client.key
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-a, --address` | `:8080` | 监听地址 |
| `--backend` | 必填 | 上游地址，可重复（轮询负载均衡） |
| `--cert` / `--key` / `--client-ca` | 空 | 监听端 TLS / mTLS |
| `--backend-ca` | 空 | 校验 backend 证书的 CA |
| `--backend-cert` / `--backend-key` | 空 | 对 backend mTLS 出示的客户端证书 |
| `-c, --config` | 空 | JSON 配置文件（与命令行参数二选一） |

## SOCKS5 代理 socks5

SOCKS5 正向代理（RFC 1928），只实现 CONNECT 命令（TCP 代理），BIND 与
UDP ASSOCIATE 返回 COMMAND NOT SUPPORTED；地址类型支持 IPv4/IPv6/域名
（域名由代理代为解析）。认证为 RFC 1929 用户名/密码子协商。

### 场景 1：本机开放代理

```bash
open-proxy.exe socks5 -a 127.0.0.1:1080
```

```bash
curl -x socks5h://127.0.0.1:1080 http://httpbin.org/get
# socks5h：目标域名交给代理解析（走 DomainName 地址类型）
# socks5 ：客户端本地解析后以 IP 请求
```

### 场景 2：用户名/密码认证

```bash
open-proxy.exe socks5 -a 0.0.0.0:1080 --user alice --password s3cret
```

```bash
curl -x socks5h://alice:s3cret@host:1080 https://example.com/
# 无凭证/错误凭证 → 子协商失败，连接被关闭
```

### 场景 3：TLS / mTLS 监听

```bash
open-proxy.exe socks5 -a 0.0.0.0:1080 \
    --cert certs/server.pem --key certs/server.key \
    --client-ca certs/ca.pem     # 可选：mTLS
```

注意 SOCKS5 over TLS **非 RFC 标准**，主流客户端（curl 的 `--socks5*`）
不支持 TLS 承载——TLS 监听面向自定义客户端（客户端以 TLS 接入后再做
SOCKS5 握手），管理中心的 socks5 资源同此。

| 参数 | 默认 | 说明 |
|---|---|---|
| `-a, --address` | `:1080` | 监听地址 |
| `--user` / `--password` | 空 | RFC 1929 认证（必须成对） |
| `--cert` / `--key` / `--client-ca` | 空 | 监听端 TLS / mTLS |
| `--dial-timeout` | 10s | 连接目标超时 |
| `--idle-timeout` | 2m | CONNECT 隧道空闲超时 |
| `-c, --config` | 空 | JSON 配置文件（与命令行参数二选一） |

## TCP 中继 relay

转发裸 TCP 流量，**不解析任何协议**：监听本地端口，把字节流原样转发到
配置的上游。适合不便于改造的私有协议、数据库连接转发等场景。

特性：

- **多上游按权重随机选择**（`host:port=weight`，weight 缺省 1）；
- **拨号失败自动切换（failover）**：选中的上游连不上时依次尝试其余
  上游，全部失败才断开客户端；最近失败的上游在下一轮选择中靠后；
- **仅拨号阶段切换**：透传一旦开始（连接已承载数据）不再切换上游；
- 本地监听端与**每个上游**均支持 TLS/mTLS（上游 TLS 可逐个配置）；
- 透传空闲超时（`idle-timeout`）自动断开，半关闭语义保证单方向结束后
  另一方向可以把剩余数据传完。

### 场景 1：单上游

```bash
open-proxy.exe relay -a :9000 --upstream 10.0.0.1:9001
```

### 场景 2：多上游加权 + failover

```bash
open-proxy.exe relay -a :9000 \
    --upstream 10.0.0.1:9001=3 \
    --upstream 10.0.0.2:9001 \
    --upstream 10.0.0.3:9001
# 权重 3:1:1 随机选择；某台上不去自动切换到其余两台
```

### 场景 3：TLS 监听 / 对上游 TLS

```bash
open-proxy.exe relay -a 0.0.0.0:9000 \
    --cert certs/server.pem --key certs/server.key \
    --client-ca certs/ca.pem \
    --upstream 10.0.0.1:9001 \
    --upstream-ca certs/ca.pem \
    --upstream-cert certs/client.pem --upstream-key certs/client.key
```

`--upstream-ca/cert/key` 作用于**全部上游**；命令行形态适合简单场景。
需要**每上游不同的 TLS**（例如一个明文、一个 mTLS）时用配置文件——
`--config` 指向结构化 JSON：

```bash
open-proxy.exe relay -c relay.json
```

```json
{
	"listen": ":9000",
	"listen_tls": { "cert": "certs/server.pem", "key": "certs/server.key" },
	"dial_timeout": "10s",
	"idle_timeout": "2m",
	"upstreams": [
		{
			"address": "10.0.0.1:9001", "weight": 3,
			"tls": { "ca": "certs/ca.pem", "cert": "certs/client.pem", "key": "certs/client.key" }
		},
		{ "address": "10.0.0.2:9001", "weight": 1 }
	]
}
```

示例见 `configs/relay.example.json`。

| 参数 | 默认 | 说明 |
|---|---|---|
| `-a, --address` | `:9000` | 监听地址 |
| `--upstream` | 必填 | 上游地址 `host:port=weight`，可重复 |
| `--cert` / `--key` / `--client-ca` | 空 | 监听端 TLS / mTLS |
| `--upstream-ca` / `--upstream-cert` / `--upstream-key` | 空 | 上游端 TLS（作用于全部上游） |
| `--dial-timeout` | 10s | 连接上游超时 |
| `--idle-timeout` | 2m | 透传空闲超时 |
| `-c, --config` | 空 | 结构化 JSON 配置文件（多上游独立 TLS，与命令行二选一） |

## 管理中心 admin

以 Web UI + REST API 统一创建/编辑/启停/删除代理资源（forward、
reverse、socks5、relay）。资源以进程内实例运行（不派生子进程），
配置持久化到 JSON 文件（重启后自动恢复运行）。

```bash
open-proxy.exe admin -a 127.0.0.1:8090 \
    --data proxies.json \
    --user admin --password s3cret \
    --cert certs/server.pem --key certs/server.key     # 可选：TLS
```

浏览器打开 `http://127.0.0.1:8090`：

- **布局**：左侧菜单（资源总览 / 各类型过滤 / 证书工具）+ 右侧内容区；
  窄屏侧栏自动收窄为图标。
- **登录**：配置了 `--user/--password` 时显示登录页，换取 12 小时会话
  令牌（localStorage 持久，刷新不掉线）；未配置认证则直接进入。
- **创建资源**：四种类型各自表单，字段与 CLI 参数语义一致（顺序按
  "本机配置在前：名称/地址 → 认证 → 监听 TLS → 上游配置"）；TLS 字段
  为 **PEM 内容**（粘贴或选择文件），随资源存入 `proxies.json`，不依赖
  服务器磁盘证书。中继的上游为动态行，每行可独立展开 TLS 配置。
- **编辑资源**：每行「编辑」按钮打开回填后的表单，保存即以新配置
  重启实例（构造失败自动回滚旧配置并恢复旧实例）；已停止的资源只
  改配置不启动。
- **动态用户管理**（forward 资源）：增删/改密即时生效，无需重启；
  密码以 salt+SHA-256 存储，明文不落盘。首次给无认证资源加用户会自动
  重启该实例启用认证。
- **证书工具**（侧栏独立菜单页）：生成自签证书（算法/曲线/RSA 位数/
  组织/附加 SAN/CA 参数/有效期），或由已有 CA 签发客户端/服务端/
  双向证书，可选导出浏览器可导入的 PKCS#12（client.pfx）；产物可
  复制、下载。生成的 CA 与证书自动持久化（`certs.json`，重启后仍在），
  页面下方已保存的记录可查看（证书/私钥 PEM）与删除。
- **运行监控**：总请求数、双向字节数（CONNECT 隧道实时入账）、按用户
  请求数、按状态码、最近 50 条请求（含目标与认证用户）。relay/socks5
  资源暂无埋点，指标显示为 0。
- 监听地址写 `127.0.0.1:0` 可随机分配端口（实际端口回显）。

| 参数 | 默认 | 说明 |
|---|---|---|
| `-a, --address` | `127.0.0.1:8090` | 管理中心监听地址 |
| `--data` | `proxies.json` | 资源持久化文件 |
| `--user` / `--password` | 空 | 登录认证（必须成对；不配则开放） |
| `--cert` / `--key` / `--client-ca` | 空 | 管理中心自身监听 TLS / mTLS |
| `-c, --config` | 空 | JSON 配置文件（与命令行参数二选一） |

## REST API 参考

认证：`Authorization: Bearer <token>`（`POST /api/login` 获取）或标准
Basic。所有错误返回 `{"error": "..."}`。

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/login` | 登录 `{user,password}` → `{token}`；未启用认证返回 `{auth:false}` |
| `DELETE` | `/api/logout` | 作废当前会话令牌 |
| `GET` | `/api/resources` | 资源列表（含状态与简要指标） |
| `POST` | `/api/resources` | 创建资源（JSON 结构见下） |
| `PUT` | `/api/resources/{id}` | **编辑资源**（完整资源 JSON，运行中以新配置重启，失败回滚） |
| `POST` | `/api/resources/{id}/start` / `stop` | 启停（停止立即断开监听与连接） |
| `DELETE` | `/api/resources/{id}` | 删除（停实例 + 移除持久化） |
| `GET` | `/api/resources/{id}/metrics` | 监控快照 |
| `GET` | `/api/resources/{id}/users` | forward 资源的用户列表 |
| `POST` | `/api/resources/{id}/users` | `{user,password}` 添加/更新用户 |
| `DELETE` | `/api/resources/{id}/users/{user}` | 删除用户 |
| `POST` | `/api/certs/generate` | 生成证书：`{common_name,days,organization,dns_names,ips,usage,ca_common_name,ca_days,algorithm,curve,rsa_bits}` → `{ca,ca_key,cert,key}` |
| `POST` | `/api/certs/issue` | 由已有 CA 签发：`{ca,ca_key,common_name,days,usage,pfx_password,...}` → `{cert,key,pfx?}`（pfx 为 base64 的 PKCS#12，浏览器导入用） |
| `GET` / `DELETE` | `/api/cas` / `/api/cas/{id}` | 已保存的 CA 记录（generate 自动持久化到 `certs.json`，重启后仍在；列表含证书与私钥 PEM） |
| `GET` / `DELETE` | `/api/certs` / `/api/certs/{id}` | 已保存的证书记录（generate/issue 自动持久化） |

创建正向资源（字段与 forward 命令参数对应，TLS 字段为 PEM 内容）：

```bash
curl -u admin:s3cret -X POST http://127.0.0.1:8090/api/resources \
  -H "Content-Type: application/json" -d '{
    "name": "出口",
    "type": "forward",
    "address": "127.0.0.1:1080",
    "forward": {
      "user": "alice", "password": "pw",
      "upstream": "https://10.0.0.2:1080",
      "upstream_user": "up", "upstream_password": "b-pass",
      "upstream_ca": "-----BEGIN CERTIFICATE-----\n...",
      "cert": "-----BEGIN CERTIFICATE-----\n...",
      "key": "-----BEGIN EC PRIVATE KEY-----\n..."
    }
  }'
```

创建反向资源：

```bash
curl -u admin:s3cret -X POST http://127.0.0.1:8090/api/resources \
  -H "Content-Type: application/json" -d '{
    "name": "站点入口",
    "type": "reverse",
    "address": "127.0.0.1:8080",
    "reverse": { "backends": ["http://127.0.0.1:9000"] }
  }'
```

创建 SOCKS5 资源（认证）：

```bash
curl -u admin:s3cret -X POST http://127.0.0.1:8090/api/resources \
  -H "Content-Type: application/json" -d '{
    "name": "socks5 出口",
    "type": "socks5",
    "address": "127.0.0.1:1080",
    "socks5": { "user": "alice", "password": "pw" }
  }'
```

创建中继资源（多上游 + 每上游独立 TLS + failover）：

```bash
curl -u admin:s3cret -X POST http://127.0.0.1:8090/api/resources \
  -H "Content-Type: application/json" -d '{
    "name": "内网中继",
    "type": "relay",
    "address": "127.0.0.1:9000",
    "relay": {
      "upstreams": [
        { "address": "10.0.0.1:9001", "weight": 3,
          "ca": "-----BEGIN CERTIFICATE-----\n...",
          "cert": "-----BEGIN CERTIFICATE-----\n...",
          "key": "-----BEGIN PRIVATE KEY-----\n..." },
        { "address": "10.0.0.2:9001" }
      ]
    }
  }'
```

编辑资源（`PUT`，body 为完整资源 JSON，ID 以路径为准）：

```bash
curl -u admin:s3cret -X PUT http://127.0.0.1:8090/api/resources/<id> \
  -H "Content-Type: application/json" -d '{ ...与创建相同的结构... }'
```

监控示例：

```bash
curl -u admin:s3cret http://127.0.0.1:8090/api/resources/<id>/metrics
# {"started_at":"...","requests":3,"bytes_in":22,"bytes_out":22,
#  "by_user":{"alice":2},"by_status":{"200":3},"recent":[...]}
```

## 架构

```
cmd/                    # CLI 接线（cobra）：forward / reverse / socks5 /
                        # relay / admin / certgen + 配置文件装载
internal/httpproxy/     # 正向代理：转发、CONNECT 隧道、代理链拨号、
                        # 认证（Credentials 单用户 / UserStore 动态多用户）、
                        # Metrics 埋点
internal/reverseproxy/  # 反向代理：轮询负载均衡、backend TLS
internal/socks5/        # SOCKS5 服务端：协议层（RFC 1928/1929）+ CONNECT
internal/relay/         # TCP 中继：加权选择、failover、双向透传
internal/certgen/       # 证书生成/签发（分步 API，多算法）
internal/netutil/       # 共享工具：空闲超时双向拷贝、写侧半关闭、
                        # TLS 配置构造（路径版/PEM 内容版）、上游 URL 解析、
                        # 测试 PKI（CA + 叶子证书）
internal/admin/         # 管理中心：资源生命周期（runner 模型）、JSON 持久化、
                        # REST API、登录会话、监控聚合、内嵌 Web UI、证书工具
configs/                # 各命令的示例配置文件
certs/                  # 测试证书与生成脚本（certgen 的备用方案）
```

代理链的实现要点：本地代理以自定义 `DialContext` 统一走"连上游 →
CONNECT → 隧道"的拨号函数，普通转发与 CONNECT 共用；对 https 目标，
`http.Transport` 在隧道内与目标直接做端到端 TLS（按系统根证书校验），
对上游的 mTLS 证书只由自己的拨号器出示，不会被出示给第三方目标。

管理中心的资源模型：每种类型构造出 `runner`（`serve` 阻塞式服务 +
`stop` 断开监听与全部连接），http 类资源包一层 `http.Server`，relay/
socks5 直接用各自的 TCP 服务——资源增删启停不需要派生子进程。

## 常见问题

**浏览器把代理配成 https:// 不通。**
多数浏览器代理设置只支持明文 http 代理；TLS 监听主要面向 curl/程序化
客户端。浏览器场景建议：本机回环明文监听 + 认证，机密性靠目标站点自身
的 HTTPS（CONNECT 隧道本就端到端加密）。

**自签证书被拒（`unknown certificate` / `bad certificate`）。**
客户端不信任自签 CA。把 CA 装入系统信任库（`certutil -addstore root
ca.pem`，Windows 需管理员），或给客户端配 CA（curl 的 `--cacert` /
`--proxy-cacert`）。open-proxy 不提供跳过校验选项。

**Windows 自带 curl 对自签证书报 `CERT_TRUST_REVOCATION_STATUS_UNKNOWN`。**
Schannel 会对自签 CA 做吊销检查；加 `--ssl-no-revoke`，或把 CA 装入系统
信任库。另注意老版本 Git Bash 自带 curl（7.7x）对 TLS 代理有已知 bug，
建议用系统 curl 或升级。

**代理链不通，上游日志显示 `remote error: tls: bad certificate`。**
A 没配 `--upstream-ca`，默认用系统根证书验证自签的 B，握手被 A 自己
拒绝。给 A 加 `--upstream-ca certs/ca.pem`。

**`-c` 配置文件与 flag 同时用报错。**
设计如此：两者二选一（`配置文件与命令行参数二选一`），避免默认值
覆盖配置的歧义。选其一即可。

**端口被占用 / exe 无法覆盖。**
Windows 下运行中的 exe 不能被覆盖，构建前先停掉旧进程；`open-proxy
forward` 默认端口 1080 常被残留实例占用，`netstat -ano | findstr :1080`
找到 PID 后 `taskkill /F /PID <pid>`。

**管理中心的资源 TLS 与管理中心自身的 TLS 是两回事。**
`open-proxy admin --cert/--key` 保护的是管理界面这一跳；代理资源的
监听/上游/backend TLS 在创建资源时以 PEM 内容单独配置。
