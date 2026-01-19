# 重复造轮子之--Socks5 代理

目前已经实现了socks5代理的功能，能够实现客户端和服务端tls加密后进行转发，防止被检测发现。且该代理为透明代理，即不解析客户端发的内容，也不需要客户端信任服务端证书。

后续再研究http代理协议，并视情况实现。

写本项目的初衷是之前使用v2ray时，总时不时被封，后来发现协议过于简单导致很容易被定位检测到，又因为自己刚学了Rust，所以就想着用Rust实现一个代理，在客户端和服务端之间使用TLS加密传输，这样就不容易被检测了。后来在编写后才发现有Trojan，但因为没有深入研究Trojan，不知道跟Trojan有多少差别。

## 目的

学习Socks5代理
学习Rust语言

## Features

透明代理，代理服务端不解析传输的数据（http协议不解析，https协议到服务端时是双重加密的）
TLS加密传输
不需要客户端信任代理的tls证书

## 编译

需要具备Rust环境，[安装Rust链接](https://rustup.rs)
步骤：

1. 将项目拷贝到本地
2. 在源码目录内执行： cargo build --release
3. 最终执行文件： target/release/proxy_rs

### 客户端配置示例

```toml
[log]
access.level = "info"
access.path = "log/access.log"

[inbound] #传入的配置
protocol = "socks5"
port = 1080

[outbound]
protocol = "ethan" #目前只支持ethan（自定义命名）和freedom
uid = "ethan" #与服务端的代理连接时会验证用户和密码，需要与服务端配置一致
pwd = "pass01!"
port = 10800   #服务端代理的端口
addr = "127.0.0.1"# 服务端代理的地址，可以是ip地址，也可以是服务端的域名。

[outbound.tls]
use_tls=true #是否使用tls
domain_name="localhost" #服务端域名，如果使用tls时，该地址必填
crt_path=""# 客户端会加载系统所有信任的证书，并加载此证书，对服务端的证书进行校验
```

### 服务端配置示例

```toml
[log]
access.level = "info"
access.path = "log/access.log"

[inbound] #传入配置
protocol = "ethan" # 传入的协议，需要与客户端报纸一致
port = 10800 
uid = "uid"
pwd = "pwd"

[inbound.tls]
use_tls = true
crt_path = "localhost.crt" 
key_path = "localhost.key"
domain_name = "localhost"

[outbound] #传出的协议，freedom表示会转发到目标服务器。
protocol = "freedom"
```

### 运行

该代理本身并不区分客户端和代理端，只是根据配置文件构建 InBound和OutBound，因此只需要将设置好配置文件，然后启动就可以实现相应的功能。

#### 客户端

```shell
 proxy_rs -c client.toml
```

#### 服务端

```shell
proxy_rs -c server.toml
```

## 进度

1. 完成socks5服务端 ✅
2. 完成socks5<->freedom的转发 ✅
3. 完成socks5<->自定义协议output<->自定义协议input<->freedom的转发 ✅
4. 自定义协议加密.✅
5. 将配置提取到文件.✅
6. socks5协议已在服务器端验证，功能已完成。✅
