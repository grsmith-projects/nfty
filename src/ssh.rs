use anyhow::{bail, Result};
use async_trait::async_trait;
use colored::Colorize;
use russh::server::{Auth, Handler, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec};
use russh_keys::key::KeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const AUTH_FILE_PATH: &str = "/data/auth.json";
const FALLBACK_AUTH_FILE_PATH: &str = "nfty-auth.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub username: String,
    pub password_sha256: String,
    pub must_change_password: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            username: "nfty".to_string(),
            password_sha256: hash_password("nfty"),
            must_change_password: true,
        }
    }
}

pub fn hash_password(pw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nfty-salt-v1:");
    hasher.update(pw.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn auth_path() -> &'static str {
    if Path::new("/data").exists() {
        AUTH_FILE_PATH
    } else {
        FALLBACK_AUTH_FILE_PATH
    }
}

pub fn load_auth_config() -> AuthConfig {
    let p = auth_path();
    match fs::read_to_string(p) {
        Ok(raw) => match serde_json::from_str::<AuthConfig>(&raw) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("[nfty-ssh] Warning: corrupt auth file {}: {}", p, e);
                AuthConfig {
                    username: "nfty".to_string(),
                    password_sha256: "locked-corrupt-auth-file".to_string(),
                    must_change_password: false,
                }
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let def = AuthConfig::default();
            let _ = save_auth_config(&def);
            def
        }
        Err(e) => {
            eprintln!("[nfty-ssh] Warning: failed to read auth file {}: {}", p, e);
            AuthConfig {
                username: "nfty".to_string(),
                password_sha256: "locked-corrupt-auth-file".to_string(),
                must_change_password: false,
            }
        }
    }
}

pub fn save_auth_config(cfg: &AuthConfig) -> Result<()> {
    let p = auth_path();
    let tmp = format!("{}.tmp.{}", p, std::process::id());
    let txt = serde_json::to_string_pretty(cfg)?;
    fs::write(&tmp, txt)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, p)?;
    Ok(())
}

pub fn verify_login(user: &str, password: &str) -> bool {
    let cfg = load_auth_config();
    cfg.username == user && cfg.password_sha256 == hash_password(password)
}

/// Reads a password from stdin with terminal echo disabled
pub fn read_password_prompt(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let stdin_fd = libc::STDIN_FILENO;
    let mut orig_termios: libc::termios = unsafe { std::mem::zeroed() };
    let is_tty = unsafe { libc::tcgetattr(stdin_fd, &mut orig_termios) == 0 };

    if is_tty {
        let mut noecho = orig_termios;
        noecho.c_lflag &= !libc::ECHO;
        unsafe {
            libc::tcsetattr(stdin_fd, libc::TCSANOW, &noecho);
        }
    }

    let mut line = String::new();
    let res = io::stdin().lock().read_line(&mut line);

    if is_tty {
        unsafe {
            libc::tcsetattr(stdin_fd, libc::TCSANOW, &orig_termios);
        }
        println!();
    }

    res?;
    Ok(line.trim_end_matches(&['\r', '\n'][..]).to_string())
}

/// Interactive password change flow (enforced on first SSH login when password is still 'nfty',
/// and also callable any time via the `password` CLI command).
pub fn interactive_change_password(forced_first_login: bool) -> Result<()> {
    if forced_first_login {
        println!(
            "\n{}",
            "=================================================================="
                .yellow()
                .bold()
        );
        println!(
            "{}",
            " ⚠ FIRST LOGIN SECURITY NOTICE: Default password ('nfty') active!"
                .yellow()
                .bold()
        );
        println!(
            "{}",
            " You must set a new password for user 'nfty' before continuing."
                .yellow()
        );
        println!(
            "{}\n",
            "=================================================================="
                .yellow()
                .bold()
        );
    }

    loop {
        let pw1 = read_password_prompt("New password for 'nfty': ")?;
        if pw1.is_empty() {
            println!("{}", "  ✖ Password cannot be empty.".red());
            continue;
        }
        if forced_first_login && pw1 == "nfty" {
            println!(
                "{}",
                "  ✖ New password cannot be the default ('nfty'). Please choose a different password."
                    .red()
            );
            continue;
        }
        let pw2 = read_password_prompt("Confirm new password: ")?;
        if pw1 != pw2 {
            println!(
                "{}",
                "  ✖ Passwords do not match. Please try again.".red()
            );
            continue;
        }

        let mut cfg = load_auth_config();
        cfg.password_sha256 = hash_password(&pw1);
        cfg.must_change_password = false;
        save_auth_config(&cfg)?;
        println!(
            "  {} Password for '{}' updated and saved!\n",
            "✔".green().bold(),
            cfg.username.bold()
        );
        return Ok(());
    }
}

pub fn enforce_first_login_password_change_if_needed() -> Result<()> {
    let cfg = load_auth_config();
    if cfg.must_change_password {
        interactive_change_password(true)?;
    }
    Ok(())
}

/// Allocates a Linux pseudo-terminal pair `(master_fd, slave_fd)` using `posix_openpt`
fn open_pty(cols: u32, rows: u32) -> Result<(RawFd, RawFd)> {
    unsafe {
        let master_fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master_fd < 0 {
            bail!("posix_openpt failed");
        }
        if libc::grantpt(master_fd) != 0 || libc::unlockpt(master_fd) != 0 {
            libc::close(master_fd);
            bail!("grantpt/unlockpt failed");
        }
        let slave_name_ptr = libc::ptsname(master_fd);
        if slave_name_ptr.is_null() {
            libc::close(master_fd);
            bail!("ptsname failed");
        }
        let slave_fd = libc::open(slave_name_ptr, libc::O_RDWR | libc::O_NOCTTY);
        if slave_fd < 0 {
            libc::close(master_fd);
            bail!("open slave pty failed");
        }

        set_pty_winsize(master_fd, cols, rows);
        Ok((master_fd, slave_fd))
    }
}

fn set_pty_winsize(fd: RawFd, cols: u32, rows: u32) {
    let ws = libc::winsize {
        ws_row: rows.max(24) as u16,
        ws_col: cols.max(80) as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        let _ = libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

struct PtySession {
    master_writer: Arc<Mutex<tokio::fs::File>>,
    master_fd: RawFd,
    cols: u32,
    rows: u32,
}

#[derive(Clone)]
struct NftySshServer {
    sessions: Arc<Mutex<HashMap<ChannelId, PtySession>>>,
    pending_dims: Arc<Mutex<HashMap<ChannelId, (u32, u32)>>>,
}

impl NftySshServer {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_dims: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl russh::server::Server for NftySshServer {
    type Handler = Self;
    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self {
        Self::new()
    }
}

#[async_trait]
impl Handler for NftySshServer {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if verify_login(user, password) {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        {
            let mut dims = self.pending_dims.lock().await;
            dims.insert(channel, (col_width, row_height));
        }
        let mut guard = self.sessions.lock().await;
        if let Some(s) = guard.get_mut(&channel) {
            s.cols = col_width;
            s.rows = row_height;
            set_pty_winsize(s.master_fd, col_width, row_height);
        }
        session.channel_success(channel);
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        {
            let mut dims = self.pending_dims.lock().await;
            dims.insert(channel, (col_width, row_height));
        }
        let mut guard = self.sessions.lock().await;
        if let Some(s) = guard.get_mut(&channel) {
            s.cols = col_width;
            s.rows = row_height;
            set_pty_winsize(s.master_fd, col_width, row_height);
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let (cols, rows) = {
            let mut dims = self.pending_dims.lock().await;
            dims.remove(&channel).unwrap_or((80, 24))
        };
        let (master_fd, slave_fd) = open_pty(cols, rows)?;
        let exe = std::env::current_exe().unwrap_or_else(|_| "/bin/nfty".into());

        // Spawn `/bin/nfty --ssh-session` attached to the slave PTY
        let mut cmd = Command::new(exe);
        cmd.arg("--ssh-session")
            .env("TERM", "xterm-256color");

        unsafe {
            let sfd = slave_fd;
            cmd.pre_exec(move || {
                libc::setsid();
                libc::ioctl(sfd, libc::TIOCSCTTY, 0);
                libc::dup2(sfd, libc::STDIN_FILENO);
                libc::dup2(sfd, libc::STDOUT_FILENO);
                libc::dup2(sfd, libc::STDERR_FILENO);
                if sfd > 2 {
                    libc::close(sfd);
                }
                Ok(())
            });
        }

        let mut child = cmd.spawn()?;
        unsafe {
            libc::close(slave_fd);
        }

        let master_read_fd = unsafe { libc::dup(master_fd) };
        let mut master_reader =
            tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(master_read_fd) });
        let master_writer = Arc::new(Mutex::new(tokio::fs::File::from_std(unsafe {
            std::fs::File::from_raw_fd(master_fd)
        })));

        {
            let mut guard = self.sessions.lock().await;
            guard.insert(
                channel,
                PtySession {
                    master_writer,
                    master_fd,
                    cols,
                    rows,
                },
            );
        }

        session.channel_success(channel);
        let handle = session.handle();
        let sessions_cleanup = self.sessions.clone();

        // Forward PTY output -> SSH channel, and close channel when child exits
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match master_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if handle
                            .data(channel, CryptoVec::from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = tokio::task::spawn_blocking(move || child.wait()).await;
            {
                let mut guard = sessions_cleanup.lock().await;
                guard.remove(&channel);
            }
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut guard = self.sessions.lock().await;
        guard.remove(&channel);
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut guard = self.sessions.lock().await;
        guard.remove(&channel);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let guard = self.sessions.lock().await;
        if let Some(s) = guard.get(&channel) {
            let mut writer = s.master_writer.lock().await;
            let _ = writer.write_all(data).await;
            let _ = writer.flush().await;
        }
        Ok(())
    }
}

const SSH_HOST_KEY_PATH: &str = "/data/ssh_host_ed25519_key";
const FALLBACK_SSH_HOST_KEY_PATH: &str = "nfty_ssh_host_ed25519_key";

fn ssh_host_key_path() -> &'static str {
    if Path::new("/data").exists() && Path::new("/data").is_dir() {
        SSH_HOST_KEY_PATH
    } else {
        FALLBACK_SSH_HOST_KEY_PATH
    }
}

pub fn load_or_create_ssh_host_key() -> KeyPair {
    let path = ssh_host_key_path();
    if Path::new(path).exists() {
        if let Ok(kp) = russh_keys::load_secret_key(path, None) {
            return kp;
        }
    }

    let kp = KeyPair::generate_ed25519();
    let mut pem_buf = Vec::new();
    if russh_keys::encode_pkcs8_pem(&kp, &mut pem_buf).is_ok() {
        let _ = fs::write(path, &pem_buf);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
    kp
}

pub fn spawn_ssh_server(bind_addr: String) {
    // Ensure default auth config and persistent SSH host key exist on boot
    let _ = load_auth_config();
    let _ = load_or_create_ssh_host_key();

    tokio::spawn(async move {
        loop {
            let mut config = russh::server::Config::default();
            config.keys.push(load_or_create_ssh_host_key());
            config.inactivity_timeout = Some(std::time::Duration::from_secs(3600));
            let config = Arc::new(config);

            let mut server = NftySshServer::new();
            if let Err(e) = server.run_on_address(config, bind_addr.as_str()).await {
                eprintln!("[nfty-ssh] SSH listener error on {}: {} (retrying in 1s)", bind_addr, e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    });
}
