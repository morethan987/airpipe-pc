//! `ap` — Airpipe PC CLI + daemon entry point.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

// ------------------------------------------------------------------ log ----

static LOG_LEVEL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(2); // Info

pub const L_WARN: u8 = 1;
pub const L_INFO: u8 = 2;
pub const L_DEBUG: u8 = 3;

pub fn log_line(level: u8, args: std::fmt::Arguments<'_>) {
    if level > LOG_LEVEL.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tag = match level {
        L_WARN => "WARN",
        L_INFO => "info",
        _ => "dbg ",
    };
    eprintln!("[{ts:>10} {tag}] {args}");
}

#[macro_export]
macro_rules! alog {
    (Warn, $($t:tt)*) => { $crate::log_line($crate::L_WARN, format_args!($($t)*)) };
    (Info, $($t:tt)*) => { $crate::log_line($crate::L_INFO, format_args!($($t)*)) };
    (Debug, $($t:tt)*) => { $crate::log_line($crate::L_DEBUG, format_args!($($t)*)) };
}

mod cli;
mod clipboard;
mod config;
mod daemon;
mod discovery;
mod ipc;
mod net;
mod pairing;
mod proto;
mod queue;
mod store;
mod transfer;
mod tray;

// ------------------------------------------------------------------ cli ----

#[derive(Parser)]
#[command(
    name = "ap",
    about = "Airpipe: PC ↔ phone clipboard/file pipe",
    version
)]
struct Args {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// start the daemon (foreground; systemd owns autostart)
    Daemon {
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        no_tray: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// daemon status
    Status,
    /// open a pairing window and wait for the phone
    Pair {
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// list paired devices
    Devices,
    /// remove a pairing by name (or --all)
    Unpair {
        name: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// send files/dirs (`-` = stdin)
    Send { paths: Vec<String> },
    /// push text to the phone (reads stdin without an argument)
    Text { text: Option<String> },
    /// follow daemon logs (journalctl)
    Log {
        #[arg(short, long)]
        follow: bool,
    },
    /// gracefully stop the daemon
    Stop,
    /// show effective config / open editor
    Config {
        #[arg(long)]
        edit: bool,
    },
    /// version info
    Version,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let code = match args.cmd {
        None | Some(Cmd::Status) => {
            if args.cmd.is_none() {
                println!("（无子命令 = status；`ap --help` 查看用法）");
            }
            cmd_status()
        }
        Some(Cmd::Daemon {
            port,
            no_tray,
            verbose,
        }) => {
            if verbose {
                LOG_LEVEL.store(L_DEBUG, std::sync::atomic::Ordering::Relaxed);
            }
            let (mut cfg, warn) = config::load();
            if let Some(w) = warn {
                eprintln!("ap: {w}");
            }
            if let Some(p) = port {
                cfg.port = Some(p);
            }
            let code = daemon::run(cfg, verbose, no_tray);
            std::process::exit(code);
        }
        Some(Cmd::Pair { timeout }) => cmd_pair(timeout),
        Some(Cmd::Devices) => cmd_devices(),
        Some(Cmd::Unpair { name, all }) => cmd_unpair(name, all),
        Some(Cmd::Send { paths }) => cmd_send(&paths),
        Some(Cmd::Text { text }) => cmd_text(text),
        Some(Cmd::Log { follow }) => cmd_log(follow),
        Some(Cmd::Stop) => cmd_stop(),
        Some(Cmd::Config { edit }) => cmd_config(edit),
        Some(Cmd::Version) => {
            println!(
                "ap {} (protocol v{})",
                env!("CARGO_PKG_VERSION"),
                proto::PROTO_VER
            );
            0
        }
    };
    ExitCode::from(code)
}

fn ipc() -> Result<cli::Ipc, u8> {
    cli::Ipc::connect().map_err(|e| {
        eprintln!("ap: {e}，请先运行 `ap daemon`");
        2u8
    })
}

fn cmd_status() -> u8 {
    let Ok(mut c) = ipc() else { return 2 };
    let st = match c.request(serde_json::json!({"cmd": "status"})) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ap: {e}");
            return 1;
        }
    };
    if st.get("ok").and_then(|o| o.as_bool()) != Some(true) {
        eprintln!("ap: {}", st.get("error").cloned().unwrap_or_default());
        return 1;
    }
    let up = st["uptime_s"].as_u64().unwrap_or(0);
    println!("运行时长   {} ({})", up, humantime(up));
    match &st["phone"] {
        serde_json::Value::Null => println!("手机       未连接"),
        p => println!(
            "手机       已连接 {} ({})，在线 {}",
            p["name"].as_str().unwrap_or("?"),
            p["ip"].as_str().unwrap_or("?"),
            humantime(p["since_s"].as_u64().unwrap_or(0))
        ),
    }
    let q = &st["queue"];
    println!(
        "队列       文本 {} / 文件 {} / {}",
        q["texts"].as_u64().unwrap_or(0),
        q["files"].as_u64().unwrap_or(0),
        daemon::human_size(q["bytes"].as_u64().unwrap_or(0))
    );
    let paired = st["paired"].as_array().cloned().unwrap_or_default();
    if paired.is_empty() {
        println!("已配对     （无 — `ap pair` 添加设备）");
    } else {
        println!("已配对     {}", paired.len());
    }
    println!("收件目录   {}", st["recv_dir"].as_str().unwrap_or("?"));
    println!("端口       {}", st["port"].as_u64().unwrap_or(0));
    0
}

fn humantime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, secs % 3600 / 60)
    }
}

fn cmd_devices() -> u8 {
    let Ok(mut c) = ipc() else { return 2 };
    let st = match c.request(serde_json::json!({"cmd": "status"})) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ap: {e}");
            return 1;
        }
    };
    let paired = st["paired"].as_array().cloned().unwrap_or_default();
    if paired.is_empty() {
        println!("（尚未配对任何设备，`ap pair` 开始）");
        return 0;
    }
    for d in paired {
        println!(
            "{:<20} {}  {}  {}",
            d["name"].as_str().unwrap_or("?"),
            &d["fingerprint"].as_str().unwrap_or("?")[..16],
            d["last_ip"].as_str().unwrap_or("-"),
            d["last_seen"].as_str().unwrap_or("-")
        );
    }
    0
}

fn cmd_pair(timeout: Option<u64>) -> u8 {
    let Ok(mut c) = ipc() else { return 2 };
    let req = serde_json::json!({"cmd": "pair", "timeout": timeout.unwrap_or(60)});
    if let Err(e) = c.send_raw(&req.to_string()) {
        eprintln!("ap: {e}");
        return 1;
    }
    let mut got_code = false;
    loop {
        match c.recv() {
            Ok(v) => {
                if let Some(code) = v.get("code").and_then(|c| c.as_str()) {
                    got_code = true;
                    println!("配对码：{code}");
                    println!(
                        "在手机 Airpipe 配对页输入此码（{} 秒内）",
                        v.get("timeout").and_then(|t| t.as_u64()).unwrap_or(60)
                    );
                } else if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                    println!("配对成功：{name}");
                    return 0;
                } else if v.get("ok").and_then(|o| o.as_bool()) == Some(true) {
                    return 0;
                } else {
                    eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
                    return 1;
                }
            }
            Err(e) => {
                if got_code && matches!(e, cli::IpcError::NotRunning | cli::IpcError::Io(_)) {
                    // daemon closed the stream when the window ended
                }
                eprintln!("ap: {e}");
                return 1;
            }
        }
    }
}

fn cmd_unpair(name: Option<String>, all: bool) -> u8 {
    if !all && name.is_none() {
        eprintln!("ap: 指定设备名或 --all");
        return 1;
    }
    let Ok(mut c) = ipc() else { return 2 };
    let target = name.unwrap_or_else(|| "all".into());
    match c.request(serde_json::json!({"cmd": "unpair", "name": target})) {
        Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => {
            println!("已删除配对：{target}");
            0
        }
        Ok(v) => {
            eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
            1
        }
        Err(e) => {
            eprintln!("ap: {e}");
            1
        }
    }
}

fn cmd_send(paths: &[String]) -> u8 {
    if paths.is_empty() {
        eprintln!("ap: ap send <路径...>（`-` = stdin）");
        return 1;
    }
    let Ok(mut c) = ipc() else { return 2 };
    if paths.len() == 1 && paths[0] == "-" {
        return match c.stream_stdin() {
            Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => {
                println!("已入队（stdin）");
                0
            }
            Ok(v) => {
                eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
                1
            }
            Err(e) => {
                eprintln!("ap: {e}");
                1
            }
        };
    }
    let abs: Vec<String> = paths
        .iter()
        .map(|p| cli::absolutize(p).display().to_string())
        .collect();
    match c.request(serde_json::json!({"cmd": "send", "paths": abs})) {
        Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => {
            println!(
                "已入队 {} 项（手机上线后自动发送）",
                v["queued"].as_u64().unwrap_or(0)
            );
            0
        }
        Ok(v) => {
            eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
            1
        }
        Err(e) => {
            eprintln!("ap: {e}");
            1
        }
    }
}

fn cmd_text(text: Option<String>) -> u8 {
    let data = match text {
        Some(t) => t,
        None => {
            use std::io::Read as _;
            let mut s = String::new();
            if std::io::stdin().read_to_string(&mut s).is_err() {
                eprintln!("ap: 读 stdin 失败");
                return 1;
            }
            s
        }
    };
    let Ok(mut c) = ipc() else { return 2 };
    match c.request(serde_json::json!({"cmd": "text", "data": data})) {
        Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => 0,
        Ok(v) => {
            eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
            1
        }
        Err(e) => {
            eprintln!("ap: {e}");
            1
        }
    }
}

fn cmd_log(follow: bool) -> u8 {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new("journalctl");
    cmd.args(["--user", "-u", "airpipe"]);
    if follow {
        cmd.arg("-f");
    }
    let err = cmd.exec();
    eprintln!("ap: journalctl 启动失败: {err}");
    1
}

fn cmd_stop() -> u8 {
    let Ok(mut c) = ipc() else { return 2 };
    match c.request(serde_json::json!({"cmd": "stop"})) {
        Ok(v) if v.get("ok").and_then(|o| o.as_bool()) == Some(true) => {
            println!("已请求停止");
            0
        }
        Ok(v) => {
            eprintln!("ap: {}", v.get("error").cloned().unwrap_or_default());
            1
        }
        Err(e) => {
            eprintln!("ap: {e}");
            1
        }
    }
}

fn cmd_config(edit: bool) -> u8 {
    if edit {
        let editor = std::env::var("EDITOR")
            .unwrap_or_else(|_| std::env::var("VISUAL").unwrap_or_else(|_| "vi".into()));
        let path = config::config_path();
        if !path.exists() {
            if let Some(p) = path.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            let _ = std::fs::write(
                &path,
                "# airpipe 配置 — 所有字段可省略\nport = 17580\nrecv_dir = \"~/Airpipe\"\n\n[clipboard]\nauto_text = true\nauto_image = true\nmax_image_mb = 20\n",
            );
        }
        match std::process::Command::new(editor).arg(&path).status() {
            Ok(s) if s.success() => return 0,
            Ok(s) => {
                eprintln!("ap: 编辑器退出码 {:?}", s.code());
                return 1;
            }
            Err(e) => {
                eprintln!("ap: 编辑器启动失败: {e}");
                return 1;
            }
        }
    }
    let (cfg, warn) = config::load();
    if let Some(w) = warn {
        eprintln!("ap: {w}");
    }
    println!("配置文件 {}", config::display(&config::config_path()));
    println!("port        = {}", cfg.port());
    println!("device_name = {}", cfg.device_name());
    println!("recv_dir    = {}", config::display(&cfg.recv_dir()));
    println!(
        "clipboard   auto_text={} auto_image={} max_image_mb={}",
        cfg.clipboard.auto_text, cfg.clipboard.auto_image, cfg.clipboard.max_image_mb
    );
    println!("身份/状态   {}", config::display(&config::state_dir()));
    0
}
