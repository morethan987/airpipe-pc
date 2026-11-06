# Airpipe PC 端 CLI 接口

**版本 v1（草案，待实现校准）** · 帧语义见根仓库 `docs/protocol.md`；本文只管人机接口。实现变动须同步更新本文并记入文末。

## 总则

- 二进制名 `ap`。**无子命令运行 = `ap help`** 。
- 除 `ap daemon` / `ap pair` 外，所有命令经 Unix 套接字与运行中的 daemon 通信；daemon 不在 → 报错退出码 `2` 并提示先 `ap daemon`。
- 退出码：`0` 成功；`1` 业务错误；`2` daemon 未运行；`130` Ctrl-C。

## 子命令

| 命令 | 形式 | 说明 |
| :--- | :--- | :--- |
| `ap daemon` | `[--port N] [--no-tray] [-v/--verbose]` | 启动守护进程，**前台阻塞**；自启动交给 systemd（根 README 有 unit 文件）。`--no-tray` 调试用 |
| `ap status` | | daemon 状态：运行时长 / 手机连接 / 队列深度 / 已配对设备 / 收件目录 / 端口 |
| `ap pair` | `[--timeout S]` | 开配对窗口（默认 60s），打印 6 位码并倒计时，等手机接入；结果即退出码 |
| `ap devices` | | 列出已配对设备（名称 / 指纹 / 最近 IP / 最近在线） |
| `ap unpair` | `<设备名> \| --all` | 删除配对记录 |
| `ap send` | `<路径...> \|\| -c/--clipboard \|\| -` | 发送文件 / 目录（目录递归，保留顶层目录名结构；**单文件一律只落文件名**，不带父目录）。**`-c` = 发送剪贴板内容**：文件引用优先，无则回退发送剪贴板图像（截图/复制的图像，等同托盘）；**`-` = stdin**（命名 `stdin-<时间戳>.bin`）。掉线则入队待手机上线 |
| `ap text` | `[<字符串>]` | 无参数时读 stdin。文本直推手机剪贴板（不经过 PC 本机剪贴板） |
| `ap log` | `[-f/--follow]` | 跟随 daemon 日志；systemd 下即 `journalctl --user -u airpipe -f` |
| `ap stop` | | 优雅停机（清 runtime socket，BYE 手机） |
| `ap config` | `[--edit]` | 无参数打印生效配置与路径；`--edit` 打开编辑器 |
| `ap completions` | `<shell>` | 导出终端 shell 自动补全脚本 |
| `ap version` | | 版本与协议版本 |

命令自动补全脚本配置方式：

```sh
# Bash
source <(ap completions bash)

# Zsh
ap completions zsh > ~/.zsh/completions/_ap

# Fish
ap completions fish > ~/.config/fish/completions/ap.fish

# Elvish
ap completions elvish > ~/.config/elvish/lib/ap.elv
```

## 管道用法（Unix 哲学位）

```bash
tar czf - logs/          | ap send -        # 归档直传，不落盘
ssh remote 'cat big.iso' | ap send -        # 远端文件借道本机进手机
echo "手机上看这句"        | ap text          # 文本推送
wl-paste                 | ap text          # 把当前剪贴板显式再推一次
```

`ap send` 多路径混合文件与目录；任一路径不可读 → 整体报错不入队（fail fast），已入队部分不回滚。顶层命名只取参数自身的文件名 / 目录名：`ap send /home/x/Airpipe/from_phone/test.pdf` 到手机即 `test.pdf`；同名文件在接收端自动追加 ` (1)` 不覆盖。

## 配置

`~/.config/airpipe/config.toml`（不存在则全自动默认）：

```toml
port = 17580            # TCP 监听 + UDP 发现端口
device_name = "<hostname>"
recv_dir = "~/Airpipe"  # 手机→PC 文件落盘根（from_phone/ 子目录）

[clipboard]
auto_text = true        # 文本自动同步
auto_image = false      # 剪贴板图片内容（截图/复制的图像）自动推送手机；复制文件不受影响
max_image_mb = 20       # 超限跳过并记日志

[transfer]
window = 4              # 文件级流水线窗口（协议 §6）：E 已发 F 未回的文件数，1..8；
                        # 1 = v1 停等（回归开关）；小文件批量时 4 约省一半时间
compression = "auto"    # 传输压缩：auto = 按扩展名跳过已压格式（zip/png/mp4/…）|
                        # always = 一律压 | never = 一律不压（回归开关）

状态与身份（**不要手改**）：`~/.local/state/airpipe/{identity.pem, paired.json}`。
运行时：`$XDG_RUNTIME_DIR/airpipe/daemon.sock`。

## 系统托盘（随 daemon 常驻）

图标：项目 logo（build.rs 自 assets/tray_icon.png 烘焙 32/64 px 点阵）。菜单：

```
📡 Airpipe — 已连接 mi-13p        ← 状态行（离线/配对窗口中 同理）
────────────────────
发送剪贴板内容            ← 文件引用优先入队；无文件引用则发送剪贴板图像（文件管理器复制、截图后点这里；等价 `ap send -c`）
配对新设备                ← 等价 ap pair，6 位码以桌面通知弹出
打开收件目录              ← xdg-open ~/Airpipe/from_phone
────────────────────
退出
```

## daemon 行为细则

- 剪贴板 watcher 分类与回声抑制规则见协议文档 §9；敏感内容（密码管理器标记）永不读取。
- 手机上线自动清空出站队列（协议 §8）。
- 收到手机文件：落盘 → sha256 校验 → 桌面通知（名称/大小）→ 文件引用写入剪贴板（可直接 Ctrl+V）。
- 日志：stderr（systemd 接管）；`-v` 开调试级别。
- 单实例：socket 绑定冲突即拒绝启动并打印现有实例信息。

## 实现规划（Rust，std 线程模型，无 async）

```
src/
├── main.rs        # clap 入口与子命令分发
├── cli.rs         # IPC 客户端侧
├── ipc.rs         # Unix socket 服务，JSON 行协议（协议文档 §10）
├── daemon.rs      # daemon 入口 + daemon/ 按职责拆分（conn/state/session/file_transfer/clipboard_sync/util）
├── proto.rs       # 帧编解码（协议文档 §5）
├── net.rs         # rustls 配置、自签证书生成（rcgen）、指纹固定验证
├── pairing.rs     # 配对窗口与码验证
├── discovery.rs   # UDP 应答线程（协议文档 §2）
├── transfer.rs    # 文件收发状态机（B/D/E/R/F/X）+ 分块压缩（ChunkEncoder/ChunkDecoder/CompMode）
├── queue.rs       # 出站引用队列（协议文档 §8）
├── clipboard/     # ClipboardBackend trait + wayland.rs（lamco-data-control）
├── store.rs       # identity.pem / paired.json
├── tray.rs        # ksni 托盘
└── config.rs
```

依赖：`clap`、`serde`/`serde_json`、`toml`、`rustls`、`rcgen`、`lamco-data-control`、`ksni`、`notify-rust`、`sha2`、`zstd`。全部纯 Rust 或平台常规库。

## 变更日志

- 2026-11-04 v1 初稿（审议中）
- 2026-11-04 v1.1：`ap send` 顶层命名只取参数自身文件名/目录名（单文件不再带父目录）；新增 `ap send -c/--clipboard`（等同托盘「发送剪贴板文件」）；`auto_image` 默认 false 并在 `ap config` 输出中释义。
- 2026-11-06 v1.2：新增 `[transfer]` 配置（`window` 1..8 默认 4、`compression` auto/always/never）；daemon.rs 拆分为 `daemon/` 模块目录；协议 v2（D 帧压缩 + 流水线窗口）；新增静态命令自动补全功能
- 2026-11-07 v1.3：`ap send -c` 与托盘「发送剪贴板内容」（原「发送剪贴板文件」）支持图像回退——剪贴板无文件引用时发送最佳图像 rendition（截图落在剪贴板的是 `image/*` 字节而非文件，此前必然报「No file references found」）；上限沿用 `max_image_mb`。
