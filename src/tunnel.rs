//! Cloudflare tunnel management for public internet sharing
//!
//! This module handles:
//! - Detecting/downloading cloudflared binary
//! - Starting a quick tunnel
//! - Parsing the public URL
//! - Cleanup on exit

use anyhow::{anyhow, Context, Result};
use regex::Regex;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

/// Represents an active tunnel connection
pub struct Tunnel {
    /// The public HTTPS URL assigned by Cloudflare
    pub url: String,
    /// The cloudflared child process
    process: Child,
}

impl Tunnel {
    /// Gracefully shut down the tunnel
    pub async fn shutdown(mut self) {
        let _ = self.process.kill().await;
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Best effort kill on drop (can't await in drop)
        #[cfg(unix)]
        {
            if let Some(pid) = self.process.id() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
        }
        #[cfg(windows)]
        {
            // On Windows, just try to kill
            let _ = self.process.start_kill();
        }
    }
}

/// Start a cloudflare tunnel for the given port
pub async fn start_tunnel(port: u16) -> Result<Tunnel> {
    // Step 1: Ensure cloudflared is available
    let cloudflared_path = ensure_cloudflared().await?;

    tracing::info!("Starting cloudflare tunnel on port {}", port);

    // Step 2: Start cloudflared process
    // Don't pipe stdout - we don't need it and it can cause blocking
    let mut process = Command::new(&cloudflared_path)
        .args(["tunnel", "--url", &format!("http://localhost:{}", port)])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("Failed to start cloudflared")?;

    // Step 3: Parse the URL from stderr
    let stderr = process.stderr.take().ok_or_else(|| anyhow!("Failed to capture stderr"))?;
    let url = parse_tunnel_url(stderr).await?;

    tracing::info!("Tunnel established: {}", url);

    // Give the tunnel a moment to fully establish
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    Ok(Tunnel { url, process })
}

/// Parse the tunnel URL from cloudflared's stderr output
/// Also spawns a background task to keep consuming stderr so cloudflared doesn't block
async fn parse_tunnel_url(stderr: tokio::process::ChildStderr) -> Result<String> {
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();

    // Regex to match the trycloudflare.com URL
    let url_regex = Regex::new(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")?;

    // Read lines until we find the URL (with timeout)
    let timeout = tokio::time::Duration::from_secs(30);
    let start = tokio::time::Instant::now();

    while start.elapsed() < timeout {
        match tokio::time::timeout(tokio::time::Duration::from_secs(5), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Some(captures) = url_regex.find(&line) {
                    let url = captures.as_str().to_string();

                    // Spawn a background task to keep consuming stderr
                    // This prevents cloudflared from blocking when its buffer fills
                    tokio::spawn(async move {
                        while let Ok(Some(_)) = lines.next_line().await {
                            // Discard remaining output
                        }
                    });

                    return Ok(url);
                }
            }
            Ok(Ok(None)) => {
                // EOF reached without finding URL
                return Err(anyhow!("cloudflared exited without providing a URL"));
            }
            Ok(Err(e)) => {
                return Err(anyhow!("Error reading cloudflared output: {}", e));
            }
            Err(_) => {
                // Timeout on this read, continue
                continue;
            }
        }
    }

    Err(anyhow!("Timeout waiting for tunnel URL"))
}

/// Ensure cloudflared binary is available (download if needed)
async fn ensure_cloudflared() -> Result<PathBuf> {
    // Check 1: Is it in our cache directory?
    let cache_dir = get_cache_dir()?;
    let cached_binary = get_binary_path(&cache_dir);

    if cached_binary.exists() {
        tracing::debug!("Using cached cloudflared: {:?}", cached_binary);
        return Ok(cached_binary);
    }

    // Check 2: Is it in system PATH?
    if let Ok(path) = which::which("cloudflared") {
        tracing::debug!("Using system cloudflared: {:?}", path);
        return Ok(path);
    }

    // Need to download it
    println!("cloudflared not found. Downloading...");
    download_cloudflared(&cache_dir).await?;
    println!("Download complete!");

    Ok(cached_binary)
}

/// Get the termshare cache directory
fn get_cache_dir() -> Result<PathBuf> {
    let base = dirs::cache_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))
        .ok_or_else(|| anyhow!("Could not determine cache directory"))?;

    let cache_dir = base.join("termshare").join("bin");
    Ok(cache_dir)
}

/// Get the platform-specific binary path
fn get_binary_path(cache_dir: &PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        cache_dir.join("cloudflared.exe")
    }
    #[cfg(not(windows))]
    {
        cache_dir.join("cloudflared")
    }
}

/// Download cloudflared for the current platform
async fn download_cloudflared(cache_dir: &PathBuf) -> Result<()> {
    // Create cache directory
    tokio::fs::create_dir_all(cache_dir).await?;

    // Determine download URL based on platform
    let (download_url, is_tgz) = get_download_url()?;
    let binary_path = get_binary_path(cache_dir);

    tracing::info!("Downloading cloudflared from: {}", download_url);

    // Download the file
    let response = reqwest::get(&download_url)
        .await
        .context("Failed to download cloudflared")?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to download cloudflared: HTTP {}",
            response.status()
        ));
    }

    let bytes = response.bytes().await?;

    if is_tgz {
        // macOS: Extract from .tgz archive
        extract_tgz(&bytes, &binary_path).await?;
    } else {
        // Linux/Windows: Direct binary
        tokio::fs::write(&binary_path, &bytes).await?;
    }

    // Make executable on Unix
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

/// Extract cloudflared from a .tgz archive (macOS)
async fn extract_tgz(data: &[u8], dest: &PathBuf) -> Result<()> {
    use std::io::Cursor;
    use flate2::read::GzDecoder;
    use tar::Archive;

    let cursor = Cursor::new(data);
    let decoder = GzDecoder::new(cursor);
    let mut archive = Archive::new(decoder);

    // Find and extract the cloudflared binary
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        if path.file_name().map(|n| n == "cloudflared").unwrap_or(false) {
            // Read the binary content
            let mut contents = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut contents)?;
            tokio::fs::write(dest, contents).await?;
            return Ok(());
        }
    }

    Err(anyhow!("cloudflared binary not found in archive"))
}

/// Get the download URL for the current platform
/// Returns (url, is_tgz) - is_tgz indicates if the download needs extraction
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
