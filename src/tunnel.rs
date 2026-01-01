use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub struct Tunnel {
    pub url: String,
    process: Child,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            if let Some(pid) = self.process.id() {
                unsafe { libc::kill(pid as i32, libc::SIGTERM); }
            }
        }
        #[cfg(windows)]
        {
            let _ = self.process.start_kill();
        }
    }
}

pub async fn start_tunnel(port: u16) -> Result<Tunnel> {
    let cloudflared_path = ensure_cloudflared().await?;

    tracing::info!("Starting cloudflare tunnel on port {}", port);

    let mut process = Command::new(&cloudflared_path)
        .args(["tunnel", "--url", &format!("http://localhost:{}", port)])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start cloudflared")?;

    let stderr = process.stderr.take().ok_or_else(|| anyhow!("Failed to capture stderr"))?;
    let url = parse_tunnel_url(stderr).await?;

    tracing::info!("Tunnel established: {}", url);

    // Let tunnel fully establish
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    Ok(Tunnel { url, process })
}

/// Parse tunnel URL and spawn background task to consume remaining stderr (prevents blocking)
async fn parse_tunnel_url(stderr: tokio::process::ChildStderr) -> Result<String> {
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();

    let url_regex = Regex::new(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")?;
    let timeout = tokio::time::Duration::from_secs(30);
    let start = tokio::time::Instant::now();

    while start.elapsed() < timeout {
        match tokio::time::timeout(tokio::time::Duration::from_secs(5), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Some(captures) = url_regex.find(&line) {
                    let url = captures.as_str().to_string();

                    // Keep consuming stderr so cloudflared doesn't block
                    tokio::spawn(async move {
                        while let Ok(Some(_)) = lines.next_line().await {}
                    });

                    return Ok(url);
                }
            }
            Ok(Ok(None)) => {
                return Err(anyhow!("cloudflared exited without providing a URL"));
            }
            Ok(Err(e)) => {
                return Err(anyhow!("Error reading cloudflared output: {}", e));
            }
            Err(_) => continue,
        }
    }

    Err(anyhow!("Timeout waiting for tunnel URL"))
}

async fn ensure_cloudflared() -> Result<PathBuf> {
    let cache_dir = get_cache_dir()?;
    let cached_binary = get_binary_path(&cache_dir);

    if cached_binary.exists() {
        tracing::debug!("Using cached cloudflared: {:?}", cached_binary);
        return Ok(cached_binary);
    }

    if let Ok(path) = which::which("cloudflared") {
        tracing::debug!("Using system cloudflared: {:?}", path);
        return Ok(path);
    }

    println!("cloudflared not found. Downloading...");
    download_cloudflared(&cache_dir).await?;
    println!("Download complete!");

    Ok(cached_binary)
}

fn get_cache_dir() -> Result<PathBuf> {
    let base = dirs::cache_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))
        .ok_or_else(|| anyhow!("Could not determine cache directory"))?;

    Ok(base.join("termshare").join("bin"))
}

fn get_binary_path(cache_dir: &PathBuf) -> PathBuf {
    #[cfg(windows)]
    { cache_dir.join("cloudflared.exe") }
    #[cfg(not(windows))]
    { cache_dir.join("cloudflared") }
}

async fn download_cloudflared(cache_dir: &PathBuf) -> Result<()> {
    tokio::fs::create_dir_all(cache_dir).await?;

    let (download_url, is_tgz) = get_download_url()?;
    let binary_path = get_binary_path(cache_dir);

    tracing::info!("Downloading cloudflared from: {}", download_url);

    let response = reqwest::get(&download_url)
        .await
        .context("Failed to download cloudflared")?;

    if !response.status().is_success() {
        return Err(anyhow!("Failed to download cloudflared: HTTP {}", response.status()));
    }

    let bytes = response.bytes().await?;

    if is_tgz {
        extract_tgz(&bytes, &binary_path).await?;
    } else {
        tokio::fs::write(&binary_path, &bytes).await?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(&binary_path).await?.permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(&binary_path, perms).await?;
    }

    tracing::info!("cloudflared downloaded to: {:?}", binary_path);
    Ok(())
}

async fn extract_tgz(data: &[u8], dest: &PathBuf) -> Result<()> {
    use std::io::Cursor;
    use flate2::read::GzDecoder;
    use tar::Archive;

    let cursor = Cursor::new(data);
    let decoder = GzDecoder::new(cursor);
    let mut archive = Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        if path.file_name().map(|n| n == "cloudflared").unwrap_or(false) {
            let mut contents = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut contents)?;
            tokio::fs::write(dest, contents).await?;
            return Ok(());
        }
    }

    Err(anyhow!("cloudflared binary not found in archive"))
}

fn get_download_url() -> Result<(String, bool)> {
    let base = "https://github.com/cloudflare/cloudflared/releases/latest/download";

    let (filename, is_tgz) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "x86_64") => ("cloudflared-darwin-amd64.tgz", true),
        ("macos", "aarch64") => ("cloudflared-darwin-arm64.tgz", true),
        ("linux", "x86_64") => ("cloudflared-linux-amd64", false),
        ("linux", "aarch64") => ("cloudflared-linux-arm64", false),
        ("windows", "x86_64") => ("cloudflared-windows-amd64.exe", false),
        (os, arch) => {
            return Err(anyhow!(
                "Unsupported platform: {} {}. Please install cloudflared manually.",
                os, arch
            ));
        }
    };

    Ok((format!("{}/{}", base, filename), is_tgz))
}
