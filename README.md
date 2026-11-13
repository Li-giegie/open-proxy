# open-proxy

HTTP/HTTPS 正向代理、反向代理与代理资源管理中心，单二进制、零运行时依赖。

```
open-proxy forward   # 正向代理：认证、代理链（上游代理）、TLS/mTLS
open-proxy reverse   # 反向代理：多 backend 负载均衡、TLS/mTLS
open-proxy admin     # 管理中心：Web UI + REST API，动态管理代理资源
```

- [构建安装](#构建安装)
- [证书生成](#证书生成)
- [正向代理 forward](#正向代理-forward)
- [代理链（正向代理级联）](#代理链正向代理级联)
- [反向代理 reverse](#反向代理-reverse)
- [管理中心 admin](#管理中心-admin)
- [REST API 参考](#rest-api-参考)
- [架构](#架构)
- [常见问题](#常见问题)

## 构建安装

要求 Go 1.22+（依赖 `net/http` 的方法路由模式匹配）。

```bash
go build -o open-proxy .
```

## 证书生成

`certs/` 目录下的文件：

| 文件 | 用途 |
|---|---|
| `gen-certs.sh` | 一键生成整套证书（Git Bash 运行；PowerShell 下 `-subj` 的 `//` 改回 `/`） |
| `server.ext` | **服务端证书扩展（可编辑）**：SAN 地址列表、EKU |
| `client.ext` | 客户端证书扩展（可编辑）：EKU |
| `ca.pem` / `ca.key` | CA 证书 / 签发私钥（10 年） |
| `server.pem` / `server.key` | 服务端证书（825 天） |
| `client.pem` / `client.key` | 客户端证书，mTLS 出示用（825 天） |

```bash
bash certs/gen-certs.sh
```

**SAN 必须覆盖客户端实际使用的地址**（Go 1.15+ 只看 SAN，CN 无效）：
客户端连什么，`server.ext` 的 `subjectAltName` 就必须含什么——连 IP 加
`IP:x.x.x.x`，连域名加 `DNS:xxx.example.com`（支持 `*.example.com`
通配符）。**多写不报错（白名单语义），少写必校验失败**。部署到新机器时
编辑 `server.ext` 追加条目、重跑脚本即可重新签发；拿不准 IP 时用域名
条目 + DNS 解析更灵活。

> 注意：`*.key` 是签发私钥，不要提交到仓库或分发；`ca.key` 建议离线保存。

三个概念在本文中反复出现，先约定：

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

## 管理中心 admin

以 Web UI + REST API 统一创建/启停/删除 forward、reverse 代理资源。
资源以进程内实例运行，配置持久化到 JSON 文件（重启后自动恢复运行）。

```bash
open-proxy.exe admin -a 127.0.0.1:8090 \
    --data proxies.json \
    --user admin --password s3cret \
    --cert certs/server.pem --key certs/server.key     # 可选：TLS
```

浏览器打开 `http://127.0.0.1:8090`：

- **登录**：配置了 `--user/--password` 时显示登录页，换取 12 小时会话
  令牌（localStorage 持久，刷新不掉线）；未配置认证则直接进入。
- **创建资源**：表单字段与 CLI 参数语义一致；TLS 字段为 **PEM 内容**
  （粘贴或选择文件），随资源存入 `proxies.json`，不依赖服务器磁盘证书。
- **动态用户管理**（forward 资源）：增删/改密即时生效，无需重启；
  密码以 salt+SHA-256 存储，明文不落盘。首次给无认证资源加用户会自动
  重启该实例启用认证。
- **运行监控**：总请求数、双向字节数（CONNECT 隧道实时入账）、按用户
  请求数、按状态码、最近 50 条请求（含目标与认证用户）。
- 监听地址写 `127.0.0.1:0` 可随机分配端口（实际端口回显）。

| 参数 | 默认 | 说明 |
|---|---|---|
| `-a, --address` | `127.0.0.1:8090` | 管理中心监听地址 |
| `--data` | `proxies.json` | 资源持久化文件 |
| `--user` / `--password` | 空 | 登录认证（必须成对；不配则开放） |
| `--cert` / `--key` / `--client-ca` | 空 | 管理中心自身监听 TLS / mTLS |

## REST API 参考

认证：`Authorization: Bearer <token>`（`POST /api/login` 获取）或标准
Basic。所有错误返回 `{"error": "..."}`。

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/api/login` | 登录 `{user,password}` → `{token}`；未启用认证返回 `{auth:false}` |
| `DELETE` | `/api/logout` | 作废当前会话令牌 |
| `GET` | `/api/resources` | 资源列表（含状态与简要指标） |
| `POST` | `/api/resources` | 创建资源（JSON 结构见下） |
| `POST` | `/api/resources/{id}/start` / `stop` | 启停（停止立即断开监听与连接） |
| `DELETE` | `/api/resources/{id}` | 删除（停实例 + 移除持久化） |
| `GET` | `/api/resources/{id}/metrics` | 监控快照 |
| `GET` | `/api/resources/{id}/users` | forward 资源的用户列表 |
| `POST` | `/api/resources/{id}/users` | `{user,password}` 添加/更新用户 |
| `DELETE` | `/api/resources/{id}/users/{user}` | 删除用户 |

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

监控示例：

```bash
curl -u admin:s3cret http://127.0.0.1:8090/api/resources/<id>/metrics
# {"started_at":"...","requests":3,"bytes_in":22,"bytes_out":22,
#  "by_user":{"alice":2},"by_status":{"200":3},"recent":[...]}
```

## 架构

```
cmd/                    # CLI 接线（cobra）：forward / reverse / admin
internal/httpproxy/     # 正向代理：转发、CONNECT 隧道、代理链拨号、
                        # 认证（Credentials 单用户 / UserStore 动态多用户）、
                        # Metrics 埋点
internal/reverseproxy/  # 反向代理：轮询负载均衡、backend TLS
internal/proxycfg/      # 共享配置构造：TLS（路径版/PEM 内容版）、上游 URL 解析
internal/admin/         # 管理中心：资源生命周期、JSON 持久化、REST API、
                        # 登录会话、监控聚合、内嵌 Web UI
certs/                  # 测试证书与生成脚本（自行替换）
```

代理链的实现要点：本地代理以自定义 `DialContext` 统一走"连上游 →
CONNECT → 隧道"的拨号函数，普通转发与 CONNECT 共用；对 https 目标，
`http.Transport` 在隧道内与目标直接做端到端 TLS（按系统根证书校验），
对上游的 mTLS 证书只由自己的拨号器出示，不会被出示给第三方目标。

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

**端口被占用 / exe 无法覆盖。**
Windows 下运行中的 exe 不能被覆盖，构建前先停掉旧进程；`open-proxy
forward` 默认端口 1080 常被残留实例占用，`netstat -ano | findstr :1080`
找到 PID 后 `taskkill /F /PID <pid>`。

**管理中心的资源 TLS 与管理中心自身的 TLS 是两回事。**
`open-proxy admin --cert/--key` 保护的是管理界面这一跳；代理资源的
监听/上游/backend TLS 在创建资源时以 PEM 内容单独配置。
