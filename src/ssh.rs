use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use colored::Colorize;
use russh::server::{Auth, Handler, Msg, Server as _, Session};
use russh::{Channel, ChannelId, CryptoVec};
use russh_keys::key::{KeyPair, PublicKey};
use russh_keys::PublicKeyBase64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
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
    if std::env::var("NFTY_SSH_AUTH").as_deref() == Ok("publickey") {
        return Ok(());
    }
    let cfg = load_auth_config();
    if cfg.must_change_password {
        interactive_change_password(true)?;
    }
    Ok(())
}

const SSH_KEYS_DIR: &str = "/data/ssh";
const FALLBACK_SSH_KEYS_DIR: &str = "nfty-ssh";

pub fn ssh_keys_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("NFTY_SSH_KEYS_DIR") {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    if Path::new("/data").exists() && Path::new("/data").is_dir() {
        PathBuf::from(SSH_KEYS_DIR)
    } else {
        PathBuf::from(FALLBACK_SSH_KEYS_DIR)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedSshPubKey {
    pub name: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub comment: Option<String>,
    pub key_base64: String,
    pub raw_line: String,
}

pub fn normalize_ssh_key_filename(name: &str) -> Result<String> {
    let clean_name = Path::new(name.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .context("Invalid SSH key filename")?;
    if clean_name.is_empty() || clean_name == "." || clean_name == ".." {
        bail!("SSH key name cannot be empty");
    }
    Ok(if clean_name.ends_with(".pub") {
        clean_name.to_string()
    } else {
        format!("{}.pub", clean_name)
    })
}

/// Parses and cryptographically validates an OpenSSH public key string
/// (`ssh-ed25519 AAAA... [comment]`, `ecdsa-sha2-nistp256 AAAA...`, `ssh-rsa AAAA...`).
pub fn parse_ssh_pubkey_str(name: &str, raw: &str) -> Result<(ParsedSshPubKey, PublicKey)> {
    let filename = normalize_ssh_key_filename(name).unwrap_or_else(|_| name.trim().to_string());
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        // Locate the key type token (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-*`, etc.) or raw base64
        let (b64_token, comment) = if let Some(algo_idx) = tokens.iter().position(|t| {
            t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("rsa-")
        }) {
            let Some(&b64) = tokens.get(algo_idx + 1) else {
                bail!("Missing base64 public key data after '{}'", tokens[algo_idx]);
            };
            let comment_part = if tokens.len() > algo_idx + 2 {
                Some(tokens[algo_idx + 2..].join(" "))
            } else {
                None
            };
            (b64, comment_part)
        } else if tokens.len() == 1 {
            (tokens[0], None)
        } else {
            bail!(
                "Invalid OpenSSH public key format (expected 'ssh-ed25519 AAAA... [comment]' or 'ssh-rsa AAAA...')"
            );
        };

        let pubkey = russh_keys::parse_public_key_base64(b64_token)
            .with_context(|| "Failed to decode OpenSSH public key")?;
        let algorithm = match &pubkey {
            PublicKey::RSA { .. } => "ssh-rsa".to_string(),
            other => other.name().to_string(),
        };
        let fingerprint = format!("SHA256:{}", pubkey.fingerprint());
        let key_base64 = pubkey.public_key_base64();
        let raw_line = match &comment {
            Some(c) if !c.is_empty() => format!("{} {} {}", algorithm, key_base64, c),
            _ => format!("{} {}", algorithm, key_base64),
        };

        return Ok((
            ParsedSshPubKey {
                name: filename,
                algorithm,
                fingerprint,
                comment,
                key_base64,
                raw_line,
            },
            pubkey,
        ));
    }

    bail!("No OpenSSH public key found in input")
}

/// Lists all `.pub` SSH public keys saved in `/data/ssh/`.
pub fn list_saved_ssh_keys() -> BTreeMap<String, Result<ParsedSshPubKey, String>> {
    let mut out = BTreeMap::new();
    let dir = ssh_keys_dir();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if name.ends_with(".pub") {
                        if let Ok(raw) = fs::read_to_string(&path) {
                            let parsed = parse_ssh_pubkey_str(name, &raw)
                                .map(|(meta, _)| meta)
                                .map_err(|e| e.to_string());
                            out.insert(name.to_string(), parsed);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Saves and validates an OpenSSH public key to `/data/ssh/<name>.pub`.
pub fn save_ssh_pubkey_file(name: &str, content: &str) -> Result<(String, ParsedSshPubKey)> {
    let filename = normalize_ssh_key_filename(name)?;
    let (parsed, _) = parse_ssh_pubkey_str(&filename, content)?;
    let dir = ssh_keys_dir();
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let full_path = dir.join(&filename);
    let formatted = format!("{}\n", parsed.raw_line);
    fs::write(&full_path, formatted)
        .with_context(|| format!("Failed to write {}", full_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&full_path, fs::Permissions::from_mode(0o600));
    }
    Ok((filename, parsed))
}

/// Deletes a saved SSH public key `/data/ssh/<name>.pub`.
pub fn delete_ssh_pubkey_file(name: &str) -> Result<String> {
    let filename = normalize_ssh_key_filename(name)?;
    let full_path = ssh_keys_dir().join(&filename);
    fs::remove_file(&full_path)
        .with_context(|| format!("Failed to remove {}/{}", ssh_keys_dir().display(), filename))?;
    Ok(filename)
}

/// Checks whether `offered` matches any authorized public key in `/data/ssh/*.pub`
/// (or `/data/ssh/authorized_keys` if present). Returns the matched key name on success.
pub fn verify_ssh_public_key(offered: &PublicKey) -> Option<String> {
    let dir = ssh_keys_dir();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if fname.ends_with(".pub") || fname == "authorized_keys" {
                if let Ok(raw) = fs::read_to_string(&path) {
                    for line in raw.lines() {
                        let trimmed = line.trim();
                        if trimmed.is_empty() || trimmed.starts_with('#') {
                            continue;
                        }
                        if let Ok((meta, pk)) = parse_ssh_pubkey_str(fname, trimmed) {
                            if &pk == offered {
                                return Some(meta.name);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Opens `nano` (or `vi`) on `/data/ssh/<name>.pub` so the user can paste/edit an SSH public key.
pub fn edit_ssh_key_interactive(
    name: &str,
    preferred_editor: Option<&str>,
) -> Result<Option<String>> {
    let dir = ssh_keys_dir();
    let _ = fs::create_dir_all(&dir);
    let filename = normalize_ssh_key_filename(name)?;
    let full_path = dir.join(&filename);
    let existed_before = full_path.exists();

    let template = format!(
        "# Global SSH Authorized Key: {}\n# Paste your OpenSSH public key line (e.g. 'ssh-ed25519 AAAA... user@host') below,\n# then save (Ctrl+O, Enter, Ctrl+X in nano).\n\n",
        filename
    );
    if !existed_before {
        let _ = fs::write(&full_path, &template);
    }

    let editor = match preferred_editor {
        Some("vi") | Some("vim") => "vi",
        Some("nano") => "nano",
        _ => {
            if Path::new("/bin/nano").exists() || Path::new("/usr/bin/nano").exists() {
                "nano"
            } else {
                "vi"
            }
        }
    };

    let status = Command::new(editor)
        .arg(&full_path)
        .env(
            "TERM",
            std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string()),
        )
        .env("TERMINFO", "/usr/share/terminfo")
        .status()
        .with_context(|| format!("Failed to launch editor '{}'", editor))?;

    if !status.success() {
        bail!("Editor '{}' exited with non-zero status", editor);
    }

    let raw = fs::read_to_string(&full_path).unwrap_or_default();
    let non_comment_lines: usize = raw
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .count();

    if non_comment_lines == 0 {
        if !existed_before {
            let _ = fs::remove_file(&full_path);
        }
        println!("  {} Aborted (empty SSH public key).", "⚠".yellow());
        return Ok(None);
    }

    match save_ssh_pubkey_file(&filename, &raw) {
        Ok((saved_name, parsed)) => {
            println!(
                "  {} Saved & validated {}/{} -> {} {}",
                "✔".green().bold(),
                dir.display(),
                saved_name.bold().cyan(),
                parsed.algorithm.yellow(),
                parsed.fingerprint.green()
            );
            Ok(Some(saved_name))
        }
        Err(e) => {
            if !existed_before {
                let _ = fs::remove_file(&full_path);
            }
            bail!("Invalid SSH public key in {}: {}", filename, e);
        }
    }
}

/// Interactive paste mode for an OpenSSH public key (`ssh paste <name>` / `ssh key paste <name>`).
pub fn paste_ssh_key_interactive(name: &str) -> Result<Option<String>> {
    let filename = normalize_ssh_key_filename(name)?;
    let dir = ssh_keys_dir();
    println!(
        "  Paste OpenSSH public key for {} below (e.g. 'ssh-ed25519 AAAA... user@host').",
        filename.bold().cyan()
    );
    println!(
        "  Press Enter after pasting (or type {} / {} on a new line, or {} to cancel):\n",
        "EOF".yellow().bold(),
        ".".yellow().bold(),
        "ABORT".red()
    );

    let stdin = io::stdin();
    let mut content = String::new();
    for line in stdin.lock().lines() {
        let l = line?;
        let trimmed = l.trim();
        if trimmed.eq_ignore_ascii_case("abort") || trimmed.eq_ignore_ascii_case("cancel") {
            println!("  {} Aborted.", "⚠".yellow());
            return Ok(None);
        }
        if trimmed.eq_ignore_ascii_case("eof") || trimmed == "." {
            break;
        }
        if trimmed.is_empty() {
            if !content.trim().is_empty() {
                break;
            }
            continue;
        }
        content.push_str(trimmed);
        content.push('\n');
        // Since an OpenSSH public key is a single line, if it already parses cleanly, finish right away!
        if parse_ssh_pubkey_str(&filename, &content).is_ok() {
            break;
        }
    }

    if content.trim().is_empty() {
        println!("  {} Aborted (nothing pasted).", "⚠".yellow());
        return Ok(None);
    }

    let (saved_name, parsed) = save_ssh_pubkey_file(&filename, &content)?;
    println!(
        "  {} Saved & validated {}/{} -> {} {}",
        "✔".green().bold(),
        dir.display(),
        saved_name.bold().cyan(),
        parsed.algorithm.yellow(),
        parsed.fingerprint.green()
    );
    Ok(Some(saved_name))
}

/// Handles `ssh ...` / `ssh key ...` CLI subcommands (`ssh`, `ssh list`, `ssh add <name> [pubkey]`, `ssh paste <name>`, `ssh vi <name>`, `ssh show <name>`, `ssh rm <name>`).
pub fn handle_ssh_cli_command(args: &[&str]) -> Result<Option<String>> {
    // Allow optional leading `key` / `keys` token so `ssh key add ...` and `ssh add ...` work identically
    let eff_args = if args
        .first()
        .map(|s| matches!(s.to_ascii_lowercase().as_str(), "key" | "keys"))
        .unwrap_or(false)
    {
        &args[1..]
    } else {
        args
    };

    let dir = ssh_keys_dir();
    if eff_args.is_empty()
        || eff_args[0].eq_ignore_ascii_case("list")
        || eff_args[0].eq_ignore_ascii_case("ls")
    {
        let saved = list_saved_ssh_keys();
        println!(
            "{}",
            format!("Saved SSH Authorized Keys ({}/):", dir.display())
                .bold()
                .cyan()
        );
        if saved.is_empty() {
            println!(
                "  {}",
                "(none — run 'ssh add <name> <ssh-ed25519 AAAA...>', 'ssh paste <name>', or 'ssh add <name>' to open nano)"
                    .dimmed()
            );
        } else {
            for (name, res) in saved {
                match res {
                    Ok(p) => {
                        let comment_suffix = p
                            .comment
                            .as_deref()
                            .map(|c| format!(" ({})", c))
                            .unwrap_or_default();
                        println!(
                            "  {} {:<24} -> {:<19} {}{}",
                            "✔".green().bold(),
                            name.bold(),
                            p.algorithm.yellow(),
                            p.fingerprint.cyan(),
                            comment_suffix.dimmed()
                        );
                    }
                    Err(e) => println!("  {} {:<24} -> {}", "✖".red(), name, e),
                }
            }
        }
        println!(
            "\n  {}",
            "Tip: 'ssh add <name> [pubkey]', 'ssh paste <name>', 'ssh vi <name>', 'ssh show <name>', 'ssh rm <name>'"
                .dimmed()
        );
        return Ok(None);
    }

    let sub = eff_args[0].to_ascii_lowercase();
    match sub.as_str() {
        "add" | "edit" | "nano" | "new" => {
            if eff_args.len() < 2 {
                bail!(
                    "Usage: ssh {} <name> [ssh-ed25519 AAAA... [comment]] (e.g. 'ssh {} laptop')",
                    sub,
                    sub
                );
            }
            if eff_args.len() >= 3 {
                let inline_key = eff_args[2..].join(" ");
                let (saved_name, parsed) = save_ssh_pubkey_file(eff_args[1], &inline_key)?;
                println!(
                    "  {} Saved & validated {}/{} -> {} {}",
                    "✔".green().bold(),
                    dir.display(),
                    saved_name.bold().cyan(),
                    parsed.algorithm.yellow(),
                    parsed.fingerprint.green()
                );
                Ok(Some(saved_name))
            } else {
                edit_ssh_key_interactive(eff_args[1], Some("nano"))
            }
        }
        "vi" | "vim" => {
            if eff_args.len() < 2 {
                bail!("Usage: ssh vi <name> (e.g. 'ssh vi laptop')");
            }
            edit_ssh_key_interactive(eff_args[1], Some("vi"))
        }
        "paste" | "import" => {
            if eff_args.len() < 2 {
                bail!("Usage: ssh paste <name> (e.g. 'ssh paste laptop')");
            }
            if eff_args.len() >= 3 {
                let inline_key = eff_args[2..].join(" ");
                let (saved_name, parsed) = save_ssh_pubkey_file(eff_args[1], &inline_key)?;
                println!(
                    "  {} Saved & validated {}/{} -> {} {}",
                    "✔".green().bold(),
                    dir.display(),
                    saved_name.bold().cyan(),
                    parsed.algorithm.yellow(),
                    parsed.fingerprint.green()
                );
                Ok(Some(saved_name))
            } else {
                paste_ssh_key_interactive(eff_args[1])
            }
        }
        "show" | "cat" | "view" => {
            if eff_args.len() < 2 {
                bail!("Usage: ssh show <name>");
            }
            let filename = normalize_ssh_key_filename(eff_args[1])?;
            let full_path = dir.join(&filename);
            let raw = fs::read_to_string(&full_path)
                .with_context(|| format!("{}/{} not found", dir.display(), filename))?;
            println!(
                "{}",
                format!("--- {}/{} ---", dir.display(), filename)
                    .bold()
                    .cyan()
            );
            if let Ok((meta, _)) = parse_ssh_pubkey_str(&filename, &raw) {
                println!(
                    "# Algorithm: {} | Fingerprint: {}",
                    meta.algorithm.yellow(),
                    meta.fingerprint.green()
                );
            }
            print!("{}", raw);
            if !raw.ends_with('\n') {
                println!();
            }
            Ok(None)
        }
        "rm" | "del" | "delete" | "remove" => {
            if eff_args.len() < 2 {
                bail!("Usage: ssh rm <name>");
            }
            let filename = delete_ssh_pubkey_file(eff_args[1])?;
            println!(
                "  {} Deleted {}/{}",
                "✔".green().bold(),
                dir.display(),
                filename.bold()
            );
            Ok(None)
        }
        _ => {
            if eff_args.len() >= 2
                && (eff_args[1].starts_with("ssh-")
                    || eff_args[1].starts_with("ecdsa-")
                    || eff_args[1].starts_with("rsa-"))
            {
                let inline_key = eff_args[1..].join(" ");
                let (saved_name, parsed) = save_ssh_pubkey_file(eff_args[0], &inline_key)?;
                println!(
                    "  {} Saved & validated {}/{} -> {} {}",
                    "✔".green().bold(),
                    dir.display(),
                    saved_name.bold().cyan(),
                    parsed.algorithm.yellow(),
                    parsed.fingerprint.green()
                );
                Ok(Some(saved_name))
            } else {
                edit_ssh_key_interactive(eff_args[0], Some("nano"))
            }
        }
    }
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
    used_publickey: bool,
}

impl NftySshServer {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            pending_dims: Arc::new(Mutex::new(HashMap::new())),
            used_publickey: false,
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
            self.used_publickey = false;
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if verify_ssh_public_key(public_key).is_some() {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if verify_ssh_public_key(public_key).is_some() {
            self.used_publickey = true;
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
        if self.used_publickey {
            cmd.env("NFTY_SSH_AUTH", "publickey");
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_verify_ssh_public_keys() {
        let test_dir = std::env::temp_dir().join(format!("nfty_ssh_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&test_dir);
        std::env::set_var("NFTY_SSH_KEYS_DIR", &test_dir);

        let kp = KeyPair::generate_ed25519();
        let pubkey = kp.clone_public_key().expect("clone_public_key");
        let b64 = pubkey.public_key_base64();
        let line = format!("ssh-ed25519 {} admin@workstation.example.com", b64);

        let (saved_name, meta) = save_ssh_pubkey_file("workstation", &line).expect("save_ssh_pubkey_file");
        assert_eq!(saved_name, "workstation.pub");
        assert_eq!(meta.algorithm, "ssh-ed25519");
        assert!(meta.fingerprint.starts_with("SHA256:"));
        assert_eq!(meta.comment.as_deref(), Some("admin@workstation.example.com"));

        let listed = list_saved_ssh_keys();
        assert!(listed.contains_key("workstation.pub"));
        assert_eq!(verify_ssh_public_key(&pubkey).as_deref(), Some("workstation.pub"));

        let other_kp = KeyPair::generate_ed25519();
        let other_pubkey = other_kp.clone_public_key().expect("other clone_public_key");
        assert!(verify_ssh_public_key(&other_pubkey).is_none());

        let deleted = delete_ssh_pubkey_file("workstation").expect("delete_ssh_pubkey_file");
        assert_eq!(deleted, "workstation.pub");
        assert!(verify_ssh_public_key(&pubkey).is_none());

        let _ = fs::remove_dir_all(&test_dir);
        std::env::remove_var("NFTY_SSH_KEYS_DIR");
    }
}
