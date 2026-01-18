# 重复造轮子之--Socks5 代理

## 目的

学习Socks5
学习Rust语言

## 进度

1. 完成socks5服务端 ✅
2. 完成socks5<->freedom的转发 ✅
3. 完成socks5<->自定义协议output<->自定义协议input<->freedom的转发 ✅
4. 自定义协议加密.✅
5. 将配置提取到文件.✅
6. socks5协议已在服务器端验证，功能已完成。✅

## Other

### 在ARM架构的MacOS上编译目标为x86_64-unknown-linux-gnu

1. 安装 命令：rustup target install x86_64-unknown-linux-gnu
2. 安装所需工具链

```shell
   # 安装基本的交叉编译工具
brew install FiloSottile/musl-cross/musl-cross
# 对于 macOS ARM，需要安装专门的工具链
brew install messense/macos-cross-toolchains/x86_64-unknown-linux-gnu
```

3. 编辑.cargo/config.toml，指定交叉编译工具

```toml
[target.x86_64-unknown-linux-gnu]
linker = "x86_64-linux-gnu-gcc"
ar = "x86_64-linux-gnu-ar"
```