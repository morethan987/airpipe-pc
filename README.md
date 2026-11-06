# airpipe-pc

Airpipe 的 Linux PC 端（Rust）：`ap` 命令 + daemon + 系统托盘。

协议契约见上级仓库 `docs/protocol.md`；CLI 接口设计见 [docs/cli.md](docs/cli.md)。

```bash
cargo build --release
strip -s target/release/ap
install -Dm755 target/release/ap ~/.local/bin/ap
```

要求实现了 (wlr-data-control 或者 ext-data-control-v1) 的 Wayland 合成器
