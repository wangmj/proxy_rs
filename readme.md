# proxy_rs

使用 Rust 实现的轻量代理程序，支持以下典型组合：

1. 客户端模式：Socks5 入站 + Ethan 出站
2. 服务端模式：Ethan 入站 + Direct 出站

其中 Ethan 是项目内自定义协议，可选 TLS 保护客户端到服务端链路。

## 1. 功能概览

1. Socks5 入站（当前只实现 Connect）。
2. Ethan 入站与出站（uid/pwd 鉴权）。
3. Direct 出站（直接连接目标地址）。
4. 支持 TOML 和 JSON 配置。
5. 路由分流：Domain / CIDR / GeoIP(country, asn) / Default。
6. DNS 策略：local / remote，支持自定义 DNS 服务器列表。
7. 日志输出到 stdout 与文件。
8. 支持 Ctrl+C 优雅退出（停止接收新连接并等待已有连接关闭）。

## 2. 架构与链路

典型客户端链路如下：

应用 -> Socks5 Inbound -> 路由匹配 -> Ethan Outbound 或 Direct Outbound

当流量走 Ethan 时：

客户端 Ethan Outbound -> 服务端 Ethan Inbound -> 服务端路由 -> Direct/Ethan Outbound -> 目标站

## 3. 构建与启动

### 3.1 环境要求

1. Rust stable（建议使用 rustup）。
2. macOS / Linux / Windows。

### 3.2 编译

```bash
cargo build --release
```

可执行文件：

```text
target/release/proxy_rs
```

### 3.3 启动参数

```text
-c, --config <FILE>
```

1. 支持 `.toml` 与 `.json`。
2. 未指定时默认读取当前目录的 `config.toml`。

### 3.4 启动示例

使用 TOML：

```bash
# 服务端
./target/release/proxy_rs -c examples/config/server.toml

# 客户端
./target/release/proxy_rs -c examples/config/client.toml
```

使用 JSON：

```bash
# 服务端
./target/release/proxy_rs -c examples/config/server.json

# 客户端
./target/release/proxy_rs -c examples/config/client.json
```

业务程序接入客户端 Socks5：

```text
127.0.0.1:1080
```

## 4. 配置模型

顶层字段如下：

1. `log`
2. `inbound`
3. `outbounds`（数组）
4. `routes`（数组）
5. `dns`（可选）

注意：当前代码按 `name` 在 `outbounds` 中查找目标出站，因此每个 outbound 都必须配置 `name`。

### 4.1 log

```toml
[log]
access.level = "info"
access.path = "log/access.log"
```

`access.level` 支持：`trace/debug/info/warn/error`。

### 4.2 inbound

Socks5：

```toml
[inbound]
protocol = "socks5"
port = 1080
# 可选，配置后可启用用户名密码认证
# uid = "test"
# pwd = "test"
```

Ethan：

```toml
[inbound]
protocol = "ethan"
port = 10800
uid = "ethan.wang"
pwd = "pass01!"

# tls配置可选，没有则使用tcp连接
[inbound.tls]
crt_path = "examples/certs/fullchain.pem"
key_path = "examples/certs/privkey.pem"
domain_name = "localhost"
```

### 4.3 outbounds

Ethan outbound：

```toml
[[outbounds]]
name = "proxy"
protocol = "ethan"
uid = "ethan.wang"
pwd = "pass01!"
port = 10800
addr = "dev.ubuntu"

#tls配置可选，与服务端保持一致
[outbounds.tls]
use_tls = true
domain_name = "dev.ubuntu"
crt_path = "examples/certs/dev.ubuntu.crt"
```

Direct outbound：

```toml
[[outbounds]]
name = "direct"
protocol = "direct"
```

### 4.4 routes

根据匹配规则rule和rule_type进行匹配，转发到to对应的oubounds，所有未匹配到的会通过rule_type="default"对应的outbounds转发
最小可用示例（建议总是包含 default）：

```toml
[[routes]]
to = "direct" 
rule = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16"
rule_type = "CIDR"

[[routes]]
to = "direct"
rule = "CN"
rule_type = "GeoIP:country"

[[routes]]
to = "direct"
rule = "AS4134,AS4837"
rule_type = "GeoIP:asn"

[[routes]]
to = "proxy"
rule = "*"
rule_type = "default"
```

`rule_type` 当前支持：

1. `domain`：域名精确匹配或通配后缀（如 `*.google.com`）。
2. `cidr`：CIDR 列表（逗号或分号分隔）。
3. `geoip:country`：国家码列表（如 `CN,US`）。
4. `geoip:asn`：ASN 列表（如 `AS4134,AS4837`）。
5. `default`：兜底规则。

### 4.5 dns

```toml
[dns]
resolver = "local"   # local 或 remote
server = ["8.8.8.8", "1.1.1.1:53"]
```

1. `local`：在本地进行域名解析，并将解析后的地址通过routes中的规则进行匹配。
2. `remote`：在服务端解析域名，在本地只进行rule_type="domain"的路由规则匹配。
3. `server` 为空时使用系统 DNS。

### 4.6 JSON 示例

可直接参考：

1. `examples/config/client.json`
2. `examples/config/server.json`

## 5. GeoIP 数据文件

GeoIP 规则依赖以下本地文件（默认相对项目根目录）：

1. `geoips/GeoLite2-City.mmdb`
2. `geoips/GeoLite2-ASN.mmdb`

若缺失，GeoIP 相关匹配会失败。

## 6. 已知限制

1. Socks5 目前仅实现 Connect，`BIND/UDP` 尚未实现。
2. Socks5 仅支持 `NoAuth` 和 `UserPwd` 两种协商方式。
3. Ethan 为私有协议，客户端与服务端版本需要匹配。

## 7. 开发与测试

```bash
cargo test
```

已验证示例配置加载测试：

```bash
cargo test example_config_load_test -- --nocapture
```

## 8. 目录参考

```text
src/
  app_config/      # 配置模型与反序列化
  factory/         # Inbound/Outbound 工厂
  socks/           # Socks5 协议与入站实现
  ethan/           # Ethan 协议与入/出站
  direct.rs        # 直连出站
  dns_resolver.rs  # DNS 解析
  geoip_helper.rs  # GeoIP 查询
  main.rs          # 程序入口
examples/config/
  client.toml
  server.toml
  client.json
  server.json
```