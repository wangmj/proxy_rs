# proxy_rs 项目说明

一个使用 Rust 实现的轻量代理程序。

项目通过不同的 Inbound 和 Outbound 组合，实现以下两类典型部署：

1. 客户端模式：Socks5 入站 + Ethan 出站
2. 服务端模式：Ethan 入站 + Direct 出站

其中 Ethan 是项目内自定义的传输协议，可选 TLS Direct 表示直连目标地址。

## 1. 项目目标与能力

### 1.1 核心目标

1. 在客户端接收 Socks5 请求。
2. 将需要代理的请求通过 Ethan over TCP/TLS 转发到服务端。
3. 在服务端转发到真实目标，并将数据回传给客户端。
4. 支持按规则分流：命中规则走远端代理，不命中本地直连。

### 1.2 当前功能

1. Socks5 入站（Connect）。
2. Ethan 入站/出站（带简单鉴权 uid/pwd）。
3. Direct 出站（直接连接目标）。
4. 可选 TLS（客户端到服务端链路）。
5. 日志输出到 stdout 和文件。
6. 路由规则分流（domain/ip，正则匹配）。

## 2. 架构说明

### 2.1 组件

1. Inbound
- socks5：监听本地端口，接受应用代理请求。
- ethan：监听服务端端口，接受客户端 Ethan 请求。

2. Outbound
- ethan：连接远端 Ethan 服务。
- Direct：直接连接目标地址。

3. 工厂
- InBoundFactory：根据配置生成 socks5 或 ethan 入站。
- OutBoundFactory：根据配置生成 ethan 或 Direct 出站。

4. 配置
- 启动时读取 TOML/JSON 配置并构建 APP_CONFIG。
- 支持 route 规则进行出站分流。

### 2.2 典型链路

客户端模式（建议）：
应用 -> Socks5 Inbound -> 规则匹配 ->
1) 命中：Ethan Outbound -> 服务端 Ethan Inbound -> Direct Outbound -> 目标站
2) 不命中：Direct Outbound -> 目标站

## 3. 构建与运行

## 3.1 环境要求

1. Rust stable（推荐通过 rustup 安装）。
2. macOS/Linux/Windows 均可，示例路径按 macOS/Linux 给出。

### 3.2 编译

在项目根目录执行：

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

指定配置文件路径。支持 `.toml` 和 `.json`。若不指定，默认读取当前目录下 `config.toml`。

## 4. 配置说明

配置文件支持 TOML 和 JSON，顶层主要包含：

1. log
2. inbound
3. outbound
4. route（可选）

### 4.1 日志配置

```toml
[log]
access.level = "info"
access.path = "log/access.log"
```

说明：

1. access.level 支持 trace/debug/info/warn/error。
2. access.path 文件不存在时会自动创建目录和文件。

### 4.2 客户端配置示例（Socks5 + Ethan）

```toml
[log]
access.level = "trace"
access.path = "log/access.log"

[inbound]
protocol = "socks5"
port = 1080

[outbound]
protocol = "ethan"
uid = "ethan.wang"
pwd = "pass01!"
port = 10800
addr = "dev.ubuntu"

[outbound.tls]
use_tls = true
domain_name = "dev.ubuntu"
crt_path = "/Users/you/certs/dev.ubuntu.crt"

[outbound.dns]
resolver = "local"
server = ["8.8.8.8"]

[route]
# 命中正则规则 -> 走远端 Ethan
# 未命中 -> 本地 Direct 直连
domain = ["(^|\\.)google\\.com$", "^github\\.com$"]
ip = ["^1\\.1\\.1\\.1$", "^8\\.8\\.8\\.[0-9]{1,3}$", "^2001:db8:.*"]
```

### 4.3 服务端配置示例（Ethan + Direct）

```toml
[log]
access.level = "info"
access.path = "log/server_access.log"

[inbound]
protocol = "ethan"
port = 10800
uid = "ethan.wang"
pwd = "pass01!"

[inbound.tls]
use_tls = true
crt_path = "examples/certs/fullchain.pem"
key_path = "examples/certs/privkey.pem"
domain_name = "localhost"

[outbound]
protocol = "Direct"
```

### 4.4 客户端 JSON 配置示例（Socks5 + Ethan）

```json
{
  "log": {
    "access": {
      "level": "trace",
      "path": "log/access.log"
    }
  },
  "inbound": {
    "protocol": "socks5",
    "port": 1080
  },
  "outbound": {
    "protocol": "ethan",
    "uid": "ethan.wang",
    "pwd": "pass01!",
    "port": 10800,
    "addr": "dev.ubuntu",
    "tls": {
      "use_tls": true,
      "domain_name": "dev.ubuntu"
    },
    "dns": {
      "resolver": "local",
      "server": ["8.8.8.8"]
    }
  },
  "route": {
    "domain": ["(^|\\.)google\\.com$", "^github\\.com$"],
    "ip": ["^1\\.1\\.1\\.1$", "^8\\.8\\.8\\.[0-9]{1,3}$", "^2001:db8:.*"]
  }
}
```

## 5. route 分流规则

### 5.1 规则语义

1. route.domain：对目标域名进行正则匹配（内部会先转小写后匹配）。
2. route.ip：对目标 IP 字符串进行正则匹配（IPv4/IPv6 都支持）。
3. domain 或 ip 任意一条命中即判定命中规则。
4. route 未配置或为空时，保持兼容行为：全部请求走 outbound。
5. 非法正则会被忽略，并记录 warn 日志。

### 5.2 正则建议

1. 建议使用 ^ 和 $ 限定边界，避免误匹配。
2. 域名点号请转义为 \\.
3. 匹配子域可用 (^|\\.)example\\.com$

## 6. DNS 解析策略

Ethan 出站支持两种策略：

1. local
- 客户端先将域名解析为 IP，再发送给服务端。

2. remote
- 客户端保留域名，服务端侧再解析。

该选项位于 outbound.dns.resolver。

## 7. 运行方式

### 7.1 使用toml配置启动服务端

客户端

```bash
./target/release/proxy_rs -c examples/config/server.toml
```

服务端

```bash
./target/release/proxy_rs -c examples/config/client.toml
```

### 7.2 使用 JSON 配置启动

服务端：

```bash
./target/release/proxy_rs -c examples/config/server.json
```

客户端：

```bash
./target/release/proxy_rs -c examples/config/client.json
```

### 7.4 业务程序接入

将浏览器或系统代理指向客户端 Socks5 监听地址，例如：

```text
127.0.0.1:1080
```

## 8. 已知限制

1. Socks5 当前主要实现 Connect 流程，Bind/Udp 仍为待实现。
2. Socks5 认证当前优先 NoAuth，其他认证方式未完成。
3. Ethan 协议为项目内协议，需客户端和服务端版本匹配。

## 9. 开发与测试

### 9.1 运行测试

```bash
cargo test
```


## 10. 目录参考

```text
src/
  app_config/          # 配置模型与反序列化
  factory/             # Inbound/Outbound 工厂
  socks/               # Socks5 协议与入站实现
  ethan/               # Ethan 协议与入/出站
  Direct.rs           # 直连出站
  dns_resolver.rs      # DNS 解析工具
  main.rs              # 程序入口
examples/config/
  client.toml
  server.toml
```