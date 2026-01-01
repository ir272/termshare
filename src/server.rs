use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    Output { data: String },
    Resize { cols: u16, rows: u16 },
    Info { session_id: String, viewers: usize, input_allowed: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    Input { data: String },
    RequestControl,
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    success: bool,
    token: Option<String>,
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthQuery {
    token: Option<String>,
}

const MAX_BUFFER_SIZE: usize = 64 * 1024;

pub struct ServerState {
    pub session_id: String,
    pub output_tx: broadcast::Sender<ServerMessage>,
    pub terminal_size: RwLock<(u16, u16)>,
    pub viewer_count: RwLock<usize>,
    pub input_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub terminal_buffer: RwLock<Vec<u8>>,
    pub password: Option<String>,
    pub valid_tokens: RwLock<HashSet<String>>,
    pub allow_input: bool,
    pub max_viewers: Option<usize>,
    pub notification_tx: broadcast::Sender<String>,
    pub session_start: std::time::Instant,
    pub total_bytes: AtomicU64,
    pub peak_viewers: AtomicUsize,
    pub total_connections: AtomicUsize,
}

impl ServerState {
    pub fn new(
        input_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        password: Option<String>,
        allow_input: bool,
        max_viewers: Option<usize>,
    ) -> Self {
        let (output_tx, _) = broadcast::channel(1024);
        let (notification_tx, _) = broadcast::channel(16);
        let session_id = generate_session_id();

        Self {
            session_id,
            output_tx,
            terminal_size: RwLock::new((80, 24)),
            viewer_count: RwLock::new(0),
            input_tx,
            terminal_buffer: RwLock::new(Vec::with_capacity(MAX_BUFFER_SIZE)),
            password,
            valid_tokens: RwLock::new(HashSet::new()),
            allow_input,
            max_viewers,
            notification_tx,
            session_start: std::time::Instant::now(),
            total_bytes: AtomicU64::new(0),
            peak_viewers: AtomicUsize::new(0),
            total_connections: AtomicUsize::new(0),
        }
    }

    pub fn requires_auth(&self) -> bool {
        self.password.is_some()
    }

    pub async fn authenticate(&self, password: &str) -> Option<String> {
        if let Some(ref session_password) = self.password {
            if password == session_password {
                let token = uuid::Uuid::new_v4().to_string();
                self.valid_tokens.write().await.insert(token.clone());
                return Some(token);
            }
        }
        None
    }

    pub async fn is_valid_token(&self, token: &str) -> bool {
        self.valid_tokens.read().await.contains(token)
    }

    pub async fn broadcast_output(&self, data: &[u8]) {
        self.total_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        {
            let mut buffer = self.terminal_buffer.write().await;
            buffer.extend_from_slice(data);

            if buffer.len() > MAX_BUFFER_SIZE {
                let excess = buffer.len() - MAX_BUFFER_SIZE;
                buffer.drain(0..excess);
            }
        }

        let encoded = base64_encode(data);
        let _ = self.output_tx.send(ServerMessage::Output { data: encoded });
    }

    pub async fn get_buffer(&self) -> Vec<u8> {
        self.terminal_buffer.read().await.clone()
    }

    pub async fn broadcast_resize(&self, cols: u16, rows: u16) {
        *self.terminal_size.write().await = (cols, rows);
        let _ = self.output_tx.send(ServerMessage::Resize { cols, rows });
    }
}

fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()[..8].to_string()
}

fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut buf = Vec::new();
    let mut encoder = Base64Encoder::new(&mut buf);
    encoder.write_all(data).unwrap();
    drop(encoder);
    String::from_utf8(buf).unwrap()
}

struct Base64Encoder<W: std::io::Write> {
    writer: W,
}

impl<W: std::io::Write> Base64Encoder<W> {
    fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: std::io::Write> std::io::Write for Base64Encoder<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        for chunk in buf.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
            let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

            let c0 = CHARS[b0 >> 2];
            let c1 = CHARS[((b0 & 0x03) << 4) | (b1 >> 4)];
            let c2 = if chunk.len() > 1 { CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)] } else { b'=' };
            let c3 = if chunk.len() > 2 { CHARS[b2 & 0x3f] } else { b'=' };

            self.writer.write_all(&[c0, c1, c2, c3])?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

pub fn create_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/ws", get(websocket_handler))
        .route("/auth", post(auth_handler))
        .route("/auth/status", get(auth_status_handler))
        .with_state(state)
}

async fn index_handler() -> impl IntoResponse {
    Html(include_str!("viewer.html"))
}

async fn auth_handler(
    State(state): State<Arc<ServerState>>,
    Json(request): Json<AuthRequest>,
) -> impl IntoResponse {
    if !state.requires_auth() {
        return Json(AuthResponse {
            success: true,
            token: Some(String::new()),
            message: "No authentication required".to_string(),
        });
    }

    match state.authenticate(&request.password).await {
        Some(token) => {
            tracing::info!("Viewer authenticated successfully");
            Json(AuthResponse {
                success: true,
                token: Some(token),
                message: "Authentication successful".to_string(),
            })
        }
        None => {
            tracing::warn!("Failed authentication attempt");
            Json(AuthResponse {
                success: false,
                token: None,
                message: "Invalid password".to_string(),
            })
        }
    }
}

async fn auth_status_handler(
    State(state): State<Arc<ServerState>>,
    Query(query): Query<AuthQuery>,
) -> impl IntoResponse {
    #[derive(Serialize)]
    struct StatusResponse {
        requires_auth: bool,
        authenticated: bool,
    }

    let requires_auth = state.requires_auth();
    let authenticated = if requires_auth {
        if let Some(token) = query.token {
            state.is_valid_token(&token).await
        } else {
            false
        }
    } else {
        true
    };

    Json(StatusResponse { requires_auth, authenticated })
}

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    token: Option<String>,
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ServerState>>,
    Query(query): Query<WsQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    if state.requires_auth() {
        let authenticated = match query.token {
            Some(ref token) if !token.is_empty() => state.is_valid_token(token).await,
            _ => false,
        };
        if !authenticated {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    if let Some(max) = state.max_viewers {
        if *state.viewer_count.read().await >= max {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state)))
}

async fn handle_socket(socket: WebSocket, state: Arc<ServerState>) {
    state.total_connections.fetch_add(1, Ordering::Relaxed);

    {
        let mut count = state.viewer_count.write().await;
        *count += 1;
        tracing::info!("Viewer connected. Total viewers: {}", *count);
        let _ = state.notification_tx.send(format!("Viewer connected ({} total)", *count));
        state.peak_viewers.fetch_max(*count, Ordering::Relaxed);
    }

    let mut rx = state.output_tx.subscribe();
    let (mut sender, mut receiver) = socket.split();

    let (cols, rows) = *state.terminal_size.read().await;
    let viewer_count = *state.viewer_count.read().await;

    let info_msg = ServerMessage::Info {
        session_id: state.session_id.clone(),
        viewers: viewer_count,
        input_allowed: state.allow_input,
    };
    let _ = sender.send(Message::Text(serde_json::to_string(&info_msg).unwrap().into())).await;

    let resize_msg = ServerMessage::Resize { cols, rows };
    let _ = sender.send(Message::Text(serde_json::to_string(&resize_msg).unwrap().into())).await;

    // Send buffered content so new viewers see existing terminal state
    let buffer = state.get_buffer().await;
    if !buffer.is_empty() {
        let encoded = base64_encode(&buffer);
        let buffer_msg = ServerMessage::Output { data: encoded };
        let _ = sender.send(Message::Text(serde_json::to_string(&buffer_msg).unwrap().into())).await;
    }

    let state_clone = state.clone();
    let allow_input = state.allow_input;

    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            let text = serde_json::to_string(&msg).unwrap();
            if sender.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Text(text) = msg {
                if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(&text) {
                    match client_msg {
                        ClientMessage::Input { data } => {
                            if allow_input {
                                if let Ok(bytes) = base64_decode(&data) {
                                    let _ = state_clone.input_tx.send(bytes).await;
                                }
                            }
                        }
                        ClientMessage::RequestControl => {
                            tracing::info!("Viewer requested control");
                        }
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    {
        let mut count = state.viewer_count.write().await;
        *count -= 1;
        tracing::info!("Viewer disconnected. Total viewers: {}", *count);
        let _ = state.notification_tx.send(format!("Viewer disconnected ({} total)", *count));
    }
}

fn base64_decode(data: &str) -> Result<Vec<u8>, ()> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn char_to_val(c: u8) -> Option<u8> {
        CHARS.iter().position(|&x| x == c).map(|p| p as u8)
    }

    let bytes: Vec<u8> = data.bytes().filter(|&b| b != b'=').collect();
    let mut result = Vec::new();

    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 { break; }

        let v0 = char_to_val(chunk[0]).ok_or(())?;
        let v1 = char_to_val(chunk[1]).ok_or(())?;
        result.push((v0 << 2) | (v1 >> 4));

        if chunk.len() > 2 {
            let v2 = char_to_val(chunk[2]).ok_or(())?;
            result.push(((v1 & 0x0f) << 4) | (v2 >> 2));

            if chunk.len() > 3 {
                let v3 = char_to_val(chunk[3]).ok_or(())?;
                result.push(((v2 & 0x03) << 6) | v3);
            }
        }
    }

    Ok(result)
}

pub async fn start_server(state: Arc<ServerState>, port: u16, expose: bool) -> anyhow::Result<()> {
    let app = create_router(state);

    let addr = if expose {
        std::net::SocketAddr::from(([0, 0, 0, 0], port))
    } else {
        std::net::SocketAddr::from(([127, 0, 0, 1], port))
    };

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Server listening on http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
