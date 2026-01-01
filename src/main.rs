mod pty;
mod server;
mod terminal;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use std::io::Read;
use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::pty::PtySession;
use crate::server::ServerState;
use crate::terminal::{read_event, write_stdout, RawModeGuard, TerminalEvent};

const DEFAULT_PORT: u16 = 3001;

#[derive(Parser, Debug)]
#[command(name = "termshare")]
#[command(version = "0.1.0")]
#[command(about = "Share your terminal with others in real-time")]
struct Args {
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,

    #[arg(long, help = "Require password to view the session")]
    password: bool,

    #[arg(long, help = "Expose to local network (bind to 0.0.0.0)")]
    expose: bool,

    #[arg(long, help = "Allow viewers to send input to the terminal")]
    allow_input: bool,

    #[arg(long, help = "Create a public tunnel (share over the internet)")]
    public: bool,

    #[arg(short = 'c', long, help = "Run a specific command instead of shell")]
    command: Option<String>,

    #[arg(long, help = "Maximum number of concurrent viewers")]
    max_viewers: Option<usize>,
}

fn get_local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter("termshare=info")
        .with_writer(std::io::stderr)
        .init();

    let password = if args.password {
        println!("Enter session password: ");
        let pass = rpassword::read_password()?;
        if pass.is_empty() {
            println!("Warning: Empty password provided. Session will be unprotected.");
            None
        } else {
            Some(pass)
        }
    } else {
        None
    };

    let (viewer_input_tx, viewer_input_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

    let state = Arc::new(ServerState::new(
        viewer_input_tx,
        password.clone(),
        args.allow_input,
        args.max_viewers,
    ));
    let session_id = state.session_id.clone();

    // Security warnings
    if args.expose && password.is_none() {
        println!();
        println!("⚠️  WARNING: Exposing to network without password protection!");
        println!("   Anyone on your network can view this terminal.");
        println!("   Consider using --password for security.");
    }

    if args.allow_input && password.is_none() {
        println!();
        println!("⚠️  WARNING: Input enabled without password protection!");
        println!("   Anyone who connects can run commands in your terminal.");
        println!("   Strongly consider using --password for security.");
    }

    if args.public && password.is_none() {
        println!();
        println!("⚠️  WARNING: Public sharing without password protection!");
        println!("   Anyone on the internet can view this terminal.");
        println!("   Strongly consider using --password for security.");
    }

    let _tunnel = if args.public {
        println!();
        println!("Starting public tunnel...");
        match tunnel::start_tunnel(args.port).await {
            Ok(t) => {
                println!("Tunnel established!");
                Some(t)
            }
            Err(e) => {
                println!("Failed to start tunnel: {}", e);
                println!("Continuing with local-only access.");
                None
            }
        }
    } else {
        None
    };

    // Startup banner
    println!();
    println!("TermShare v0.1.0 - Terminal Sharing Tool");
    println!("=========================================");
    println!();

    if let Some(ref t) = _tunnel {
        println!("🌐 Public URL: {}", t.url);
        println!("   (HTTPS secured, anyone can connect)");
        println!();
        println!("Local URL:  http://localhost:{}", args.port);
    } else if args.expose {
        println!("Local URL:   http://localhost:{}", args.port);
        if let Some(ip) = get_local_ip() {
            println!("Network URL: http://{}:{}", ip, args.port);
        }
        println!();
        println!("(Use --public to share over the internet)");
    } else {
        println!("Share URL: http://localhost:{}", args.port);
        println!();
        println!("(Use --expose for LAN, --public for internet)");
    }

    println!();
    println!("Session ID: {}", session_id);
    println!("Password protected: {}", if password.is_some() { "Yes" } else { "No" });
    println!("Viewer input: {}", if args.allow_input { "Enabled" } else { "View only" });
    println!("Max viewers: {}", args.max_viewers.map_or("Unlimited".to_string(), |n| n.to_string()));
    if let Some(ref cmd) = args.command {
        println!("Command: {}", cmd);
    }
    println!();
    if args.command.is_some() {
        println!("Starting command...");
    } else {
        println!("Starting shell session...");
    }
    println!("Press Ctrl+Q to exit");
    println!();

    let server_state = state.clone();
    let port = args.port;
    let expose = args.expose || args.public;
    tokio::spawn(async move {
        if let Err(e) = server::start_server(server_state, port, expose).await {
            tracing::error!("Server error: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    run_session(state.clone(), viewer_input_rx, args.command).await?;

    // Session statistics
    let duration = state.session_start.elapsed();
    let mins = duration.as_secs() / 60;
    let secs = duration.as_secs() % 60;
    let total_bytes = state.total_bytes.load(std::sync::atomic::Ordering::Relaxed);
    let peak_viewers = state.peak_viewers.load(std::sync::atomic::Ordering::Relaxed);
    let total_connections = state.total_connections.load(std::sync::atomic::Ordering::Relaxed);

    println!();
    println!("Session ended.");
    println!();
    println!("Session Statistics:");
    println!("  Duration: {}m {}s", mins, secs);
    println!("  Peak viewers: {}", peak_viewers);
    println!("  Total connections: {}", total_connections);
    if total_bytes < 1024 {
        println!("  Data transferred: {} bytes", total_bytes);
    } else if total_bytes < 1024 * 1024 {
        println!("  Data transferred: {:.1} KB", total_bytes as f64 / 1024.0);
    } else {
        println!("  Data transferred: {:.2} MB", total_bytes as f64 / (1024.0 * 1024.0));
    }
    println!();
    println!("Goodbye!");
    Ok(())
}

async fn run_session(
    state: Arc<ServerState>,
    mut viewer_input_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    command: Option<String>,
) -> Result<()> {
    let mut pty = PtySession::new(command.as_deref())?;
    let _raw_guard = RawModeGuard::new()?;

    let (pty_output_tx, pty_output_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut pty_reader = pty.try_clone_reader()?;

    let reader_handle = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match pty_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if pty_output_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("PTY read error: {}", e);
                    break;
                }
            }
        }
    });

    let mut notification_rx = state.notification_tx.subscribe();

    loop {
        while let Ok(output) = pty_output_rx.try_recv() {
            write_stdout(&output)?;
            state.broadcast_output(&output).await;
        }

        while let Ok(input) = viewer_input_rx.try_recv() {
            pty.write(&input)?;
        }

        while let Ok(notification) = notification_rx.try_recv() {
            let styled = format!("\r\n\x1b[33m[TermShare] {}\x1b[0m\r\n", notification);
            write_stdout(styled.as_bytes())?;
            state.broadcast_output(styled.as_bytes()).await;
        }

        if let Some(event) = read_event(Duration::from_millis(10))? {
            match event {
                TerminalEvent::Key(bytes) => {
                    pty.write(&bytes)?;
                }
                TerminalEvent::Quit => {
                    break;
                }
                TerminalEvent::Resize { cols, rows } => {
                    pty.resize(cols, rows)?;
                    state.broadcast_resize(cols, rows).await;
                }
            }
        }

        if reader_handle.is_finished() {
            break;
        }

        tokio::task::yield_now().await;
    }

    let _ = reader_handle.join();
    Ok(())
}
