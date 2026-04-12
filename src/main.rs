use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Multipart, Path as AxumPath, Query, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use rand::{distributions::Alphanumeric, Rng};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tokio::{fs, io::AsyncWriteExt};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;
use urlencoding::encode;

const MESSAGES_REVISION_KEY: &str = "messages_revision";

#[derive(Clone)]
struct AppState {
    db_path: PathBuf,
    files_dir: PathBuf,
    temp_dir: PathBuf,
    runtime_config: Arc<RwLock<RuntimeConfig>>,
    startup_config: StartupConfig,
    sessions: Arc<Mutex<HashMap<String, SessionRecord>>>,
}

#[derive(Clone)]
struct RuntimeConfig {
    users: Vec<RuntimeUser>,
    session_ttl_seconds: i64,
    single_upload_limit_bytes: i64,
    single_upload_limit_label: String,
}

#[derive(Clone)]
struct RuntimeUser {
    user_id: String,
    password: String,
}

#[derive(Clone)]
struct SessionRecord {
    expire_at: i64,
    user_id: String,
}

struct AuthSession {
    user_id: String,
}

#[derive(Clone)]
struct StartupConfig {
    allow_web_restart: bool,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Serialize)]
struct HealthBody {
    ok: bool,
}

#[derive(Serialize)]
struct PublicConfigBody {
    single_upload_limit_bytes: i64,
    single_upload_limit_label: String,
}

#[derive(Serialize)]
struct OkBody {
    ok: bool,
}

#[derive(Deserialize)]
struct AuthRequest {
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    token: String,
    user_id: String,
}

#[derive(Deserialize)]
struct TextRequest {
    text: String,
}

#[derive(Deserialize)]
struct DeleteRequest {
    ids: Vec<i64>,
}

#[derive(Serialize)]
struct DeleteResponse {
    deleted: usize,
}

#[derive(Serialize)]
struct RestartResponse {
    accepted: bool,
    message: String,
}

#[derive(Deserialize)]
struct UploadInitRequest {
    file_key: String,
    file_name: String,
    file_size: i64,
    mime_type: Option<String>,
}

#[derive(Serialize)]
struct UploadInitResponse {
    upload_id: String,
    chunk_size: usize,
    parallel_limit: usize,
    received_bytes: i64,
    total_bytes: i64,
    completed_parts: Vec<UploadedPartDto>,
    done: bool,
}

#[derive(Serialize)]
struct UploadedPartDto {
    start_byte: i64,
    end_byte: i64,
    checksum: String,
}

#[derive(Serialize)]
struct UploadChunkResponse {
    upload_id: String,
    received_bytes: i64,
    total_bytes: i64,
    done: bool,
}

#[derive(Deserialize)]
struct UploadCompleteRequest {
    upload_id: String,
}

#[derive(Deserialize)]
struct UploadCancelRequest {
    upload_id: String,
}

#[derive(Serialize)]
struct UploadCancelResponse {
    cancelled: bool,
}

#[derive(Deserialize)]
struct UiStateUpdateRequest {
    chat_height_px: Option<i64>,
    input_height_px: Option<i64>,
    text_wrap_enabled: Option<bool>,
    text_zoom_scale: Option<f64>,
}

#[derive(Serialize)]
struct UiStateResponse {
    chat_height_px: Option<i64>,
    input_height_px: Option<i64>,
    text_wrap_enabled: Option<bool>,
    text_zoom_scale: Option<f64>,
}

#[derive(Serialize)]
struct VideoProgressResponse {
    position_seconds: f64,
}

#[derive(Deserialize)]
struct VideoProgressRequest {
    position_seconds: f64,
}

#[derive(Serialize)]
struct TextProgressResponse {
    line_number: i64,
}

#[derive(Deserialize)]
struct TextProgressRequest {
    line_number: i64,
}

#[derive(Debug)]
struct UploadedPart {
    start_byte: i64,
    end_byte: i64,
    checksum: String,
}

#[derive(Serialize)]
struct MessageDto {
    id: i64,
    kind: String,
    text: Option<String>,
    created_at: String,
    file_id: Option<String>,
    file_name: Option<String>,
    file_size: Option<i64>,
    mime_type: Option<String>,
    file_url: Option<String>,
    download_url: Option<String>,
}

#[derive(Deserialize)]
struct FileRoutePath {
    file_id: String,
    display_name: String,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.message })).into_response()
    }
}

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn create_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn user_id_from_password(password: &str) -> String {
    let digest = sha256_hex(password.as_bytes());
    format!("u_{}", &digest[..16])
}

fn parse_runtime_users(raw: &str) -> Vec<RuntimeUser> {
    let mut users = Vec::new();
    for password in raw.split(',').map(str::trim).filter(|value| !value.is_empty()) {
        let user = RuntimeUser {
            user_id: user_id_from_password(password),
            password: password.to_string(),
        };
        if users.iter().all(|existing: &RuntimeUser| existing.user_id != user.user_id) {
            users.push(user);
        }
    }

    users
}

fn parse_upload_limit_spec(raw: &str) -> Result<(i64, String), AppError> {
    let value = raw.trim().to_uppercase().replace(' ', "");
    if value.is_empty() {
        return Ok((5_i64 * 1024 * 1024 * 1024, "5 GB".to_string()));
    }

    let (number_text, unit, unit_bytes) = if let Some(prefix) = value.strip_suffix("GB") {
        (prefix, "GB", 1024_f64 * 1024_f64 * 1024_f64)
    } else if let Some(prefix) = value.strip_suffix("MB") {
        (prefix, "MB", 1024_f64 * 1024_f64)
    } else {
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FASTFILE_SINGLE_UPLOAD_LIMIT 只支持 MB 或 GB 单位，例如 512MB 或 5GB",
        ));
    };

    let number = number_text.parse::<f64>().map_err(|_| {
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FASTFILE_SINGLE_UPLOAD_LIMIT 数值格式无效，例如 512MB、5GB、5.25GB",
        )
    })?;
    if !number.is_finite() || number <= 0.0 {
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FASTFILE_SINGLE_UPLOAD_LIMIT 必须大于 0",
        ));
    }

    let bytes = (number * unit_bytes).round();
    if bytes <= 0.0 || bytes > i64::MAX as f64 {
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "FASTFILE_SINGLE_UPLOAD_LIMIT 超出可支持范围",
        ));
    }

    Ok((bytes as i64, format!("{} {}", number_text, unit)))
}

impl RuntimeConfig {
    fn find_user_by_password(&self, password: &str) -> Option<&RuntimeUser> {
        self.users.iter().find(|user| user.password == password)
    }

    fn has_user_id(&self, user_id: &str) -> bool {
        self.users.iter().any(|user| user.user_id == user_id)
    }

    fn primary_user_id(&self) -> &str {
        self.users
            .first()
            .map(|user| user.user_id.as_str())
            .unwrap_or("u_legacy")
    }
}

fn get_cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some(v) = pair.strip_prefix("fastfile_token=") {
            return Some(v.to_string());
        }
    }
    None
}

fn get_auth_token(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    get_cookie_token(headers)
}

fn user_scoped_key(user_id: &str, key: &str) -> String {
    format!("{user_id}:{key}")
}

fn messages_revision_meta_key(user_id: &str) -> String {
    user_scoped_key(user_id, MESSAGES_REVISION_KEY)
}

fn scoped_upload_file_key(user_id: &str, file_key: &str) -> String {
    format!("{user_id}:{file_key}")
}

async fn require_auth(headers: &HeaderMap, state: &AppState) -> Result<AuthSession, AppError> {
    let token = get_auth_token(headers).ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "未授权"))?;
    let cfg = {
        let cfg = state.runtime_config.read().await;
        cfg.clone()
    };
    let now = Utc::now().timestamp();
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "会话锁异常"))?;

    match sessions.get(&token).cloned() {
        Some(record) if record.expire_at > now && cfg.has_user_id(&record.user_id) => {
            sessions.insert(
                token.clone(),
                SessionRecord {
                    expire_at: now + cfg.session_ttl_seconds,
                    user_id: record.user_id.clone(),
                },
            );
            Ok(AuthSession { user_id: record.user_id })
        }
        _ => {
            sessions.remove(&token);
            Err(AppError::new(StatusCode::UNAUTHORIZED, "未授权"))
        }
    }
}

fn open_conn(db_path: &Path) -> Result<Connection, AppError> {
    let conn = Connection::open(db_path)
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("数据库打开失败: {e}")))?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("数据库等待超时设置失败: {e}")))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("数据库 WAL 设置失败: {e}")))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("数据库同步级别设置失败: {e}")))?;
    Ok(conn)
}

fn ensure_message_belongs_to_user(conn: &Connection, user_id: &str, message_id: i64) -> Result<(), AppError> {
    conn.query_row(
        "SELECT 1 FROM messages WHERE id = ?1 AND user_id = ?2",
        params![message_id, user_id],
        |_| Ok(()),
    )
    .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "消息不存在"))
}

fn ensure_file_belongs_to_user(conn: &Connection, user_id: &str, file_id: &str) -> Result<(), AppError> {
    conn.query_row(
        "SELECT 1 FROM messages WHERE file_id = ?1 AND user_id = ?2",
        params![file_id, user_id],
        |_| Ok(()),
    )
    .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "文件不存在"))
}

fn init_storage(
    storage_root: &Path,
    files_dir: &Path,
    temp_dir: &Path,
    db_path: &Path,
    primary_user_id: &str,
) -> Result<(), AppError> {
    std::fs::create_dir_all(storage_root)
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("创建存储目录失败: {e}")))?;
    std::fs::create_dir_all(files_dir)
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("创建文件目录失败: {e}")))?;
    std::fs::create_dir_all(temp_dir)
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("创建临时目录失败: {e}")))?;

    let conn = open_conn(db_path)?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            text_content TEXT,
            file_id TEXT UNIQUE,
            file_name TEXT,
            file_size INTEGER,
            mime_type TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS upload_sessions (
            upload_id TEXT PRIMARY KEY,
            file_key TEXT UNIQUE NOT NULL,
            file_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT,
            received_bytes INTEGER NOT NULL,
            temp_path TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS upload_chunks (
            upload_id TEXT NOT NULL,
            start_byte INTEGER NOT NULL,
            end_byte INTEGER NOT NULL,
            chunk_size INTEGER NOT NULL,
            checksum_hex TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (upload_id, start_byte)
        );
        CREATE TABLE IF NOT EXISTS ui_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS video_progress (
            file_id TEXT PRIMARY KEY,
            position_seconds REAL NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS text_progress (
            message_id INTEGER PRIMARY KEY,
            line_number INTEGER NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS app_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        ",
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("建表失败: {e}")))?;
    migrate_user_scoped_storage(&conn, primary_user_id)?;
    seed_messages_revision(&conn, primary_user_id)?;
    Ok(())
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, AppError> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn
        .prepare(&pragma)
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取表结构失败: {e}")))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取表结构失败: {e}")))?;
    for row in rows {
        if row.map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取表结构失败: {e}")))? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn migrate_user_scoped_storage(conn: &Connection, primary_user_id: &str) -> Result<(), AppError> {
    if !table_has_column(conn, "messages", "user_id")? {
        conn.execute("ALTER TABLE messages ADD COLUMN user_id TEXT NOT NULL DEFAULT ''", [])
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("迁移 messages.user_id 失败: {e}")))?;
    }
    conn.execute(
        "UPDATE messages SET user_id = ?1 WHERE user_id = '' OR user_id IS NULL",
        params![primary_user_id],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("迁移消息归属失败: {e}")))?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_user_id_id ON messages(user_id, id)",
        [],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("创建消息索引失败: {e}")))?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_user_id_file_id ON messages(user_id, file_id)",
        [],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("创建消息文件索引失败: {e}")))?;

    if !table_has_column(conn, "upload_sessions", "user_id")? {
        conn.execute("ALTER TABLE upload_sessions ADD COLUMN user_id TEXT NOT NULL DEFAULT ''", [])
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("迁移 upload_sessions.user_id 失败: {e}")))?;
    }
    conn.execute(
        "UPDATE upload_sessions SET user_id = ?1 WHERE user_id = '' OR user_id IS NULL",
        params![primary_user_id],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("迁移上传会话归属失败: {e}")))?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_upload_sessions_user_status ON upload_sessions(user_id, status, updated_at)",
        [],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("创建上传会话索引失败: {e}")))?;
    Ok(())
}

fn get_meta_value(conn: &Connection, key: &str) -> Result<Option<String>, AppError> {
    let mut stmt = conn
        .prepare("SELECT value FROM app_meta WHERE key = ?1")
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取元信息失败: {e}")))?;
    match stmt.query_row(params![key], |row| row.get::<_, String>(0)) {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("读取元信息失败: {e}"),
        )),
    }
}

fn set_meta_value(conn: &Connection, key: &str, value: &str) -> Result<(), AppError> {
    conn.execute(
        "INSERT INTO app_meta (key, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![key, value, now_iso()],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("写入元信息失败: {e}")))?;
    Ok(())
}

fn seed_messages_revision(conn: &Connection, user_id: &str) -> Result<i64, AppError> {
    let revision_key = messages_revision_meta_key(user_id);
    if let Some(existing) = get_meta_value(conn, &revision_key)? {
        return Ok(existing.parse::<i64>().unwrap_or(0).max(0));
    }

    let revision = conn
        .query_row(
            "SELECT COALESCE(MAX(id), 0) FROM messages WHERE user_id = ?1",
            params![user_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取消息修订号失败: {e}")))?
        .max(0);
    set_meta_value(conn, &revision_key, &revision.to_string())?;
    Ok(revision)
}

fn bump_messages_revision(conn: &Connection, user_id: &str) -> Result<i64, AppError> {
    let revision_key = messages_revision_meta_key(user_id);
    let next = seed_messages_revision(conn, user_id)? + 1;
    set_meta_value(conn, &revision_key, &next.to_string())?;
    Ok(next)
}

fn format_messages_revision_etag(revision: i64) -> String {
    format!("\"messages-{revision}\"")
}

fn if_none_match_matches_revision(headers: &HeaderMap, revision: i64) -> bool {
    let expected = format_messages_revision_etag(revision);
    let raw = match headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        Some(value) => value,
        None => return false,
    };
    raw.split(',').map(str::trim).any(|candidate| {
        candidate == "*"
            || candidate == expected
            || candidate.trim_matches('"') == format!("messages-{revision}")
    })
}

fn row_to_dto(row: &rusqlite::Row<'_>) -> rusqlite::Result<MessageDto> {
    let kind: String = row.get("kind")?;
    let file_id: Option<String> = row.get("file_id")?;
    let file_name: Option<String> = row.get("file_name")?;
    let file_url = file_id.as_ref().map(|fid| {
        let display = encode(file_name.as_deref().unwrap_or("file"));
        format!("/f/{fid}/{display}")
    });
    let download_url = file_url.as_ref().map(|v| format!("{v}?download=1"));

    Ok(MessageDto {
        id: row.get("id")?,
        kind,
        text: row.get("text_content")?,
        created_at: row.get("created_at")?,
        file_id,
        file_name,
        file_size: row.get("file_size")?,
        mime_type: row.get("mime_type")?,
        file_url,
        download_url,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn load_uploaded_parts(conn: &Connection, upload_id: &str) -> Result<Vec<UploadedPart>, AppError> {
    let mut stmt = conn
        .prepare(
            "SELECT start_byte, end_byte, checksum_hex FROM upload_chunks WHERE upload_id = ?1 ORDER BY start_byte ASC",
        )
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("查询分片失败: {e}")))?;
    let rows = stmt
        .query_map(params![upload_id], |row| {
            Ok(UploadedPart {
                start_byte: row.get(0)?,
                end_byte: row.get(1)?,
                checksum: row.get(2)?,
            })
        })
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取分片失败: {e}")))?;

    let mut parts = Vec::new();
    for row in rows {
        parts.push(row.map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取分片失败: {e}")))?);
    }
    Ok(parts)
}

fn total_uploaded_bytes(parts: &[UploadedPart]) -> i64 {
    parts.iter().map(|part| part.end_byte - part.start_byte).sum()
}

fn parse_range_header(range_header: &str, total_size: u64) -> Result<Option<(u64, u64)>, AppError> {
    if total_size == 0 {
        return Ok(None);
    }

    let value = range_header.trim();
    if !value.starts_with("bytes=") {
        return Ok(None);
    }
    let spec = &value[6..];
    if spec.contains(',') {
        return Err(AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "暂不支持多段下载"));
    }

    let (start_raw, end_raw) = spec
        .split_once('-')
        .ok_or_else(|| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "Range 格式错误"))?;

    let last_index = total_size - 1;
    if start_raw.is_empty() {
        let suffix = end_raw
            .parse::<u64>()
            .map_err(|_| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "Range 格式错误"))?;
        if suffix == 0 {
            return Err(AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "Range 超出范围"));
        }
        let start = total_size.saturating_sub(suffix);
        return Ok(Some((start, last_index)));
    }

    let start = start_raw
        .parse::<u64>()
        .map_err(|_| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "Range 格式错误"))?;
    let end = if end_raw.is_empty() {
        last_index
    } else {
        end_raw
            .parse::<u64>()
            .map_err(|_| AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "Range 格式错误"))?
    };

    if start > end || start >= total_size {
        return Err(AppError::new(StatusCode::RANGE_NOT_SATISFIABLE, "Range 超出范围"));
    }

    Ok(Some((start, end.min(last_index))))
}

fn get_ui_state_value(conn: &Connection, key: &str) -> Result<Option<i64>, AppError> {
    let value = conn
        .query_row(
            "SELECT value FROM ui_state WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .ok();
    Ok(value.and_then(|v| v.parse::<i64>().ok()))
}

fn set_ui_state_value(conn: &Connection, key: &str, value: i64) -> Result<(), AppError> {
    conn.execute(
        "INSERT INTO ui_state (key, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![key, value.to_string(), now_iso()],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("保存界面状态失败: {e}")))?;
    Ok(())
}

fn get_ui_state_bool(conn: &Connection, key: &str) -> Result<Option<bool>, AppError> {
    Ok(get_ui_state_value(conn, key)?.map(|value| value != 0))
}

fn set_ui_state_bool(conn: &Connection, key: &str, value: bool) -> Result<(), AppError> {
    set_ui_state_value(conn, key, if value { 1 } else { 0 })
}

fn get_ui_state_f64(conn: &Connection, key: &str) -> Result<Option<f64>, AppError> {
    let value = conn
        .query_row(
            "SELECT value FROM ui_state WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .ok();
    Ok(value.and_then(|v| v.parse::<f64>().ok()))
}

fn set_ui_state_f64(conn: &Connection, key: &str, value: f64) -> Result<(), AppError> {
    conn.execute(
        "INSERT INTO ui_state (key, value, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        params![key, value.to_string(), now_iso()],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("保存界面状态失败: {e}")))?;
    Ok(())
}

fn delete_ui_state_key(conn: &Connection, key: &str) -> Result<(), AppError> {
    conn.execute("DELETE FROM ui_state WHERE key = ?1", params![key])
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("重置界面状态失败: {e}")))?;
    Ok(())
}

async fn no_cache_middleware(req: Request<Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    resp
}

async fn index_page() -> Html<&'static str> {
    Html(include_str!("../index.html"))
}

async fn healthz() -> Json<HealthBody> {
    Json(HealthBody { ok: true })
}

async fn public_config(State(state): State<AppState>) -> Json<PublicConfigBody> {
    let cfg = state.runtime_config.read().await.clone();
    Json(PublicConfigBody {
        single_upload_limit_bytes: cfg.single_upload_limit_bytes,
        single_upload_limit_label: cfg.single_upload_limit_label,
    })
}

async fn auth(
    State(state): State<AppState>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    let cfg = state.runtime_config.read().await.clone();
    let user = cfg
        .find_user_by_password(&payload.password)
        .cloned()
        .ok_or_else(|| AppError::new(StatusCode::FORBIDDEN, "密码错误"))?;

    let token = create_token();
    let now = Utc::now().timestamp();
    {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "会话锁异常"))?;
        sessions.insert(
            token.clone(),
            SessionRecord {
                expire_at: now + cfg.session_ttl_seconds,
                user_id: user.user_id.clone(),
            },
        );
    }

    let cookie = format!(
        "fastfile_token={}; Max-Age={}; HttpOnly; SameSite=Strict; Path=/",
        token, cfg.session_ttl_seconds
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Cookie 设置失败"))?,
    );

    Ok((
        headers,
        Json(AuthResponse {
            token,
            user_id: user.user_id,
        }),
    ))
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    if let Some(token) = get_auth_token(&headers) {
        if let Ok(mut sessions) = state.sessions.lock() {
            sessions.remove(&token);
        }
    }

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_static("fastfile_token=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"),
    );

    Ok((resp_headers, Json(OkBody { ok: true })))
}

async fn list_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let auth = require_auth(&headers, &state).await?;

    let conn = open_conn(&state.db_path)?;
    let revision = seed_messages_revision(&conn, &auth.user_id)?;
    let etag = format_messages_revision_etag(revision);

    if if_none_match_matches_revision(&headers, revision) {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        response.headers_mut().insert(
            header::ETAG,
            HeaderValue::from_str(&etag)
                .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "消息修订头生成失败"))?,
        );
        return Ok(response);
    }

    let mut stmt = conn
        .prepare(
            "SELECT id, kind, text_content, created_at, file_id, file_name, file_size, mime_type FROM messages WHERE user_id = ?1 ORDER BY id ASC",
        )
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("查询失败: {e}")))?;
    let rows = stmt
        .query_map(params![auth.user_id], row_to_dto)
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取失败: {e}")))?;

    let mut out = Vec::new();
    for row in rows {
        out.push(
            row.map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取行失败: {e}")))?,
        );
    }

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::ETAG,
        HeaderValue::from_str(&etag)
            .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "消息修订头生成失败"))?,
    );
    Ok((response_headers, Json(out)).into_response())
}

async fn get_ui_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UiStateResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    let conn = open_conn(&state.db_path)?;
    Ok(Json(UiStateResponse {
        chat_height_px: get_ui_state_value(&conn, &user_scoped_key(&auth.user_id, "chat_height_px"))?,
        input_height_px: get_ui_state_value(&conn, &user_scoped_key(&auth.user_id, "input_height_px"))?,
        text_wrap_enabled: get_ui_state_bool(&conn, &user_scoped_key(&auth.user_id, "text_wrap_enabled"))?,
        text_zoom_scale: get_ui_state_f64(&conn, &user_scoped_key(&auth.user_id, "text_zoom_scale"))?,
    }))
}

async fn update_ui_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UiStateUpdateRequest>,
) -> Result<Json<UiStateResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    let conn = open_conn(&state.db_path)?;
    if let Some(height) = payload.chat_height_px {
        if !(320..=2000).contains(&height) {
            return Err(AppError::new(StatusCode::BAD_REQUEST, "聊天区高度超出范围"));
        }
        set_ui_state_value(&conn, &user_scoped_key(&auth.user_id, "chat_height_px"), height)?;
    }
    if let Some(height) = payload.input_height_px {
        if !(110..=900).contains(&height) {
            return Err(AppError::new(StatusCode::BAD_REQUEST, "输入框高度超出范围"));
        }
        set_ui_state_value(&conn, &user_scoped_key(&auth.user_id, "input_height_px"), height)?;
    }
    if let Some(enabled) = payload.text_wrap_enabled {
        set_ui_state_bool(&conn, &user_scoped_key(&auth.user_id, "text_wrap_enabled"), enabled)?;
    }
    if let Some(scale) = payload.text_zoom_scale {
        if !scale.is_finite() || scale <= 0.0 {
            return Err(AppError::new(StatusCode::BAD_REQUEST, "文本缩放比例无效"));
        }
        set_ui_state_f64(&conn, &user_scoped_key(&auth.user_id, "text_zoom_scale"), scale)?;
    }

    Ok(Json(UiStateResponse {
        chat_height_px: get_ui_state_value(&conn, &user_scoped_key(&auth.user_id, "chat_height_px"))?,
        input_height_px: get_ui_state_value(&conn, &user_scoped_key(&auth.user_id, "input_height_px"))?,
        text_wrap_enabled: get_ui_state_bool(&conn, &user_scoped_key(&auth.user_id, "text_wrap_enabled"))?,
        text_zoom_scale: get_ui_state_f64(&conn, &user_scoped_key(&auth.user_id, "text_zoom_scale"))?,
    }))
}

async fn reset_ui_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UiStateResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;
    let conn = open_conn(&state.db_path)?;
    delete_ui_state_key(&conn, &user_scoped_key(&auth.user_id, "chat_height_px"))?;
    delete_ui_state_key(&conn, &user_scoped_key(&auth.user_id, "input_height_px"))?;
    delete_ui_state_key(&conn, &user_scoped_key(&auth.user_id, "text_wrap_enabled"))?;
    delete_ui_state_key(&conn, &user_scoped_key(&auth.user_id, "text_zoom_scale"))?;
    Ok(Json(UiStateResponse {
        chat_height_px: None,
        input_height_px: None,
        text_wrap_enabled: None,
        text_zoom_scale: None,
    }))
}

async fn get_video_progress(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(file_id): AxumPath<String>,
) -> Result<Json<VideoProgressResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    let conn = open_conn(&state.db_path)?;
    ensure_file_belongs_to_user(&conn, &auth.user_id, &file_id)?;
    let position = conn
        .query_row(
            "SELECT position_seconds FROM video_progress WHERE file_id = ?1",
            params![file_id],
            |row| row.get::<_, f64>(0),
        )
        .unwrap_or(0.0);

    Ok(Json(VideoProgressResponse {
        position_seconds: position.max(0.0),
    }))
}

async fn update_video_progress(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(file_id): AxumPath<String>,
    Json(payload): Json<VideoProgressRequest>,
) -> Result<Json<VideoProgressResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    if !payload.position_seconds.is_finite() || payload.position_seconds < 0.0 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "播放进度无效"));
    }

    let conn = open_conn(&state.db_path)?;
    ensure_file_belongs_to_user(&conn, &auth.user_id, &file_id)?;
    conn.execute(
        "INSERT INTO video_progress (file_id, position_seconds, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(file_id) DO UPDATE SET position_seconds = excluded.position_seconds, updated_at = excluded.updated_at",
        params![file_id, payload.position_seconds, now_iso()],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("保存视频进度失败: {e}")))?;

    Ok(Json(VideoProgressResponse {
        position_seconds: payload.position_seconds,
    }))
}

async fn get_text_progress(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(message_id): AxumPath<i64>,
) -> Result<Json<TextProgressResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    let conn = open_conn(&state.db_path)?;
    ensure_message_belongs_to_user(&conn, &auth.user_id, message_id)?;
    let line_number = conn
        .query_row(
            "SELECT line_number FROM text_progress WHERE message_id = ?1",
            params![message_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(1);

    Ok(Json(TextProgressResponse {
        line_number: line_number.max(1),
    }))
}

async fn update_text_progress(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(message_id): AxumPath<i64>,
    Json(payload): Json<TextProgressRequest>,
) -> Result<Json<TextProgressResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    if payload.line_number <= 0 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "文本行号无效"));
    }

    let conn = open_conn(&state.db_path)?;
    ensure_message_belongs_to_user(&conn, &auth.user_id, message_id)?;
    conn.execute(
        "INSERT INTO text_progress (message_id, line_number, updated_at) VALUES (?1, ?2, ?3) ON CONFLICT(message_id) DO UPDATE SET line_number = excluded.line_number, updated_at = excluded.updated_at",
        params![message_id, payload.line_number, now_iso()],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("保存文本进度失败: {e}")))?;

    Ok(Json(TextProgressResponse {
        line_number: payload.line_number,
    }))
}

async fn create_text_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<TextRequest>,
) -> Result<Json<MessageDto>, AppError> {
    let auth = require_auth(&headers, &state).await?;
    let cfg = state.runtime_config.read().await.clone();
    let text_bytes = i64::try_from(payload.text.as_bytes().len())
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "文本数据过大"))?;
    if text_bytes > cfg.single_upload_limit_bytes {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            format!("单次上传数据不能超过 {}", cfg.single_upload_limit_label),
        ));
    }

    let mut conn = open_conn(&state.db_path)?;
    let tx = conn
        .transaction()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("开启事务失败: {e}")))?;
    tx.execute(
        "INSERT INTO messages (user_id, kind, text_content, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![auth.user_id, "text", payload.text, now_iso()],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("写入失败: {e}")))?;

    let id = tx.last_insert_rowid();
    bump_messages_revision(&tx, &auth.user_id)?;
    let dto = {
        let mut stmt = tx
            .prepare("SELECT * FROM messages WHERE id = ?1")
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("查询失败: {e}")))?;
        stmt.query_row(params![id], row_to_dto)
            .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "消息不存在"))?
    };

    tx.commit()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("提交事务失败: {e}")))?;

    Ok(Json(dto))
}

async fn create_file_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<Json<MessageDto>, AppError> {
    let auth = require_auth(&headers, &state).await?;
    let cfg = state.runtime_config.read().await.clone();

    let mut found = false;
    let mut file_id = String::new();
    let mut file_name = String::new();
    let mut mime_type = String::from("application/octet-stream");
    let mut file_size: i64 = 0;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, format!("读取上传失败: {e}")))?
    {
        if field.name() != Some("file") {
            continue;
        }
        found = true;
        file_id = create_token();
        file_name = field.file_name().unwrap_or("file").to_string();
        if let Some(ct) = field.content_type() {
            mime_type = ct.to_string();
        }

        let path = state.files_dir.join(&file_id);
        let mut out = fs::File::create(&path)
            .await
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("创建文件失败: {e}")))?;

        let mut stream_field = field;
        while let Some(chunk) = stream_field
            .chunk()
            .await
            .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, format!("读取分片失败: {e}")))?
        {
            file_size += i64::try_from(chunk.len())
                .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "文件过大"))?;
            if file_size > cfg.single_upload_limit_bytes {
                let _ = fs::remove_file(&path).await;
                return Err(AppError::new(
                    StatusCode::BAD_REQUEST,
                    format!("单次上传数据不能超过 {}", cfg.single_upload_limit_label),
                ));
            }
            out.write_all(&chunk)
                .await
                .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("写入文件失败: {e}")))?;
        }
        break;
    }

    if !found {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "缺少文件"));
    }

    let mut conn = open_conn(&state.db_path)?;
    let tx = conn
        .transaction()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("开启事务失败: {e}")))?;
    tx.execute(
        "INSERT INTO messages (user_id, kind, file_id, file_name, file_size, mime_type, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![auth.user_id, "file", file_id, file_name, file_size, mime_type, now_iso()],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("写入失败: {e}")))?;

    let id = tx.last_insert_rowid();
    bump_messages_revision(&tx, &auth.user_id)?;
    let dto = {
        let mut stmt = tx
            .prepare("SELECT * FROM messages WHERE id = ?1")
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("查询失败: {e}")))?;
        stmt.query_row(params![id], row_to_dto)
            .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "消息不存在"))?
    };

    tx.commit()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("提交事务失败: {e}")))?;

    Ok(Json(dto))
}

async fn init_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UploadInitRequest>,
) -> Result<Json<UploadInitResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;
    let cfg = state.runtime_config.read().await.clone();

    if payload.file_key.trim().is_empty() {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "file_key 不能为空"));
    }
    if payload.file_name.trim().is_empty() {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "file_name 不能为空"));
    }
    if payload.file_size <= 0 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "file_size 必须大于 0"));
    }
    if payload.file_size > cfg.single_upload_limit_bytes {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            format!("单次上传数据不能超过 {}", cfg.single_upload_limit_label),
        ));
    }

    let chunk_size = 4 * 1024 * 1024;
    let parallel_limit = 4;
    let conn = open_conn(&state.db_path)?;
    let scoped_file_key = scoped_upload_file_key(&auth.user_id, &payload.file_key);

    let existing = conn
        .query_row(
            "SELECT upload_id, file_name, file_size, mime_type, received_bytes, temp_path, status FROM upload_sessions WHERE file_key = ?1 AND user_id = ?2",
            params![scoped_file_key, auth.user_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .ok();

    if let Some((upload_id, file_name, file_size, _mime, _received, temp_path, status)) = existing {
        if status == "uploading" && file_name == payload.file_name && file_size == payload.file_size {
            let parts = load_uploaded_parts(&conn, &upload_id)?;
            let received = total_uploaded_bytes(&parts).min(payload.file_size);
            conn.execute(
                "UPDATE upload_sessions SET received_bytes = ?1, updated_at = ?2 WHERE upload_id = ?3",
                params![received, now_iso(), upload_id],
            )
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("更新会话失败: {e}")))?;
            return Ok(Json(UploadInitResponse {
                upload_id,
                chunk_size,
                parallel_limit,
                received_bytes: received,
                total_bytes: payload.file_size,
                completed_parts: parts
                    .into_iter()
                    .map(|part| UploadedPartDto {
                        start_byte: part.start_byte,
                        end_byte: part.end_byte,
                        checksum: part.checksum,
                    })
                    .collect(),
                done: received >= payload.file_size,
            }));
        }

        conn.execute(
            "DELETE FROM upload_sessions WHERE upload_id = ?1",
            params![upload_id],
        )
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("清理旧会话失败: {e}")))?;
        conn.execute(
            "DELETE FROM upload_chunks WHERE upload_id = ?1",
            params![upload_id],
        )
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("清理旧分片失败: {e}")))?;

        let _ = fs::remove_file(temp_path).await;
    }

    let upload_id = create_token();
    let temp_path = state.temp_dir.join(format!("{upload_id}.part"));
    fs::File::create(&temp_path)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("创建临时文件失败: {e}")))?;

    conn.execute(
        "INSERT INTO upload_sessions (upload_id, user_id, file_key, file_name, file_size, mime_type, received_bytes, temp_path, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'uploading', ?9, ?9)",
        params![
            upload_id,
            auth.user_id,
            scoped_file_key,
            payload.file_name,
            payload.file_size,
            payload.mime_type,
            0_i64,
            temp_path.to_string_lossy().to_string(),
            now_iso()
        ],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("创建上传会话失败: {e}")))?;

    Ok(Json(UploadInitResponse {
        upload_id,
        chunk_size,
        parallel_limit,
        received_bytes: 0,
        total_bytes: payload.file_size,
        completed_parts: Vec::new(),
        done: false,
    }))
}

async fn upload_chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<UploadChunkResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    let upload_id = headers
        .get("x-upload-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| AppError::new(StatusCode::BAD_REQUEST, "缺少 x-upload-id"))?;
    let start_byte = headers
        .get("x-start-byte")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i64>().ok())
        .ok_or_else(|| AppError::new(StatusCode::BAD_REQUEST, "缺少 x-start-byte"))?;
    let checksum = headers
        .get("x-chunk-sha256")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| AppError::new(StatusCode::BAD_REQUEST, "缺少 x-chunk-sha256"))?;
    let incoming = i64::try_from(body.len())
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "分片过大"))?;
    let end_byte = start_byte + incoming;
    if start_byte < 0 || incoming <= 0 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "分片范围无效"));
    }

    let conn = open_conn(&state.db_path)?;
    let (file_size, _received_bytes, temp_path, status): (i64, i64, String, String) = conn
        .query_row(
            "SELECT file_size, received_bytes, temp_path, status FROM upload_sessions WHERE upload_id = ?1 AND user_id = ?2",
            params![upload_id, auth.user_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "上传会话不存在"))?;

    if status != "uploading" {
        return Err(AppError::new(StatusCode::CONFLICT, "上传会话不可用"));
    }

    if end_byte > file_size {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "分片超出文件总大小"));
    }

    let actual_checksum = sha256_hex(&body);
    if actual_checksum != checksum {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "分片校验失败"));
    }

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&temp_path)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("打开临时文件失败: {e}")))?;

    file.seek(std::io::SeekFrom::Start(u64::try_from(start_byte).unwrap_or(0)))
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("定位临时文件失败: {e}")))?;
    file.write_all(&body)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("写入分片失败: {e}")))?;

    let mut conn = open_conn(&state.db_path)?;
    let tx = conn
        .transaction()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("开启事务失败: {e}")))?;

    let existing_same: Option<(i64, i64, String)> = tx
        .query_row(
            "SELECT start_byte, end_byte, checksum_hex FROM upload_chunks WHERE upload_id = ?1 AND start_byte = ?2",
            params![upload_id, start_byte],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .ok();

    if let Some((_, existing_end, existing_checksum)) = existing_same {
        if existing_end != end_byte || existing_checksum != checksum {
            return Err(AppError::new(StatusCode::CONFLICT, "分片校验不匹配"));
        }
        let uploaded: i64 = tx
            .query_row(
                "SELECT COALESCE(SUM(end_byte - start_byte), 0) FROM upload_chunks WHERE upload_id = ?1",
                params![upload_id],
                |row| row.get(0),
            )
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("统计上传进度失败: {e}")))?;
        return Ok(Json(UploadChunkResponse {
            upload_id,
            received_bytes: uploaded,
            total_bytes: file_size,
            done: uploaded >= file_size,
        }));
    }

    let overlap_count: i64 = tx
        .query_row(
            "SELECT COUNT(1) FROM upload_chunks WHERE upload_id = ?1 AND start_byte < ?3 AND end_byte > ?2",
            params![upload_id, start_byte, end_byte],
            |row| row.get(0),
        )
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("查询分片冲突失败: {e}")))?;

    if overlap_count > 0 {
        return Err(AppError::new(StatusCode::CONFLICT, "分片范围与已有数据重叠"));
    }

    tx.execute(
        "INSERT INTO upload_chunks (upload_id, start_byte, end_byte, chunk_size, checksum_hex, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![upload_id, start_byte, end_byte, incoming, checksum, now_iso()],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("记录分片失败: {e}")))?;

    let new_received: i64 = tx
        .query_row(
            "SELECT COALESCE(SUM(end_byte - start_byte), 0) FROM upload_chunks WHERE upload_id = ?1",
            params![upload_id],
            |row| row.get(0),
        )
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("统计上传进度失败: {e}")))?;
    let done = new_received >= file_size;

    tx.execute(
        "UPDATE upload_sessions SET received_bytes = ?1, updated_at = ?2 WHERE upload_id = ?3",
        params![new_received, now_iso(), upload_id],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("更新上传进度失败: {e}")))?;
    tx.commit()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("提交事务失败: {e}")))?;

    Ok(Json(UploadChunkResponse {
        upload_id,
        received_bytes: new_received,
        total_bytes: file_size,
        done,
    }))
}

async fn complete_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UploadCompleteRequest>,
) -> Result<Json<MessageDto>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    let mut conn = open_conn(&state.db_path)?;
    let (file_name, file_size, mime_type, received_bytes, temp_path, status): (
        String,
        i64,
        Option<String>,
        i64,
        String,
        String,
    ) = conn
        .query_row(
            "SELECT file_name, file_size, mime_type, received_bytes, temp_path, status FROM upload_sessions WHERE upload_id = ?1 AND user_id = ?2",
            params![payload.upload_id, auth.user_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "上传会话不存在"))?;

    if status != "uploading" {
        return Err(AppError::new(StatusCode::CONFLICT, "上传会话不可完成"));
    }

    if received_bytes < file_size {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            format!("文件尚未上传完成，已上传 {received_bytes}/{file_size}"),
        ));
    }

    let parts = load_uploaded_parts(&conn, &payload.upload_id)?;
    let mut expected_start = 0_i64;
    for part in &parts {
        if part.start_byte != expected_start {
            return Err(AppError::new(StatusCode::CONFLICT, "文件分片不完整，无法合并"));
        }
        expected_start = part.end_byte;
    }
    if expected_start != file_size {
        return Err(AppError::new(StatusCode::CONFLICT, "文件分片尚未完整上传"));
    }

    let file_id = create_token();
    let final_path = state.files_dir.join(&file_id);
    if let Err(rename_err) = fs::rename(&temp_path, &final_path).await {
        fs::copy(&temp_path, &final_path)
            .await
            .map_err(|e| {
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("搬运文件失败: {rename_err}; copy fallback failed: {e}"),
                )
            })?;
        let _ = fs::remove_file(&temp_path).await;
    }

    let tx = conn
        .transaction()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("开启事务失败: {e}")))?;

    tx.execute(
        "INSERT INTO messages (user_id, kind, file_id, file_name, file_size, mime_type, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            auth.user_id,
            "file",
            file_id,
            file_name,
            file_size,
            mime_type.unwrap_or_else(|| "application/octet-stream".to_string()),
            now_iso()
        ],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("写入消息失败: {e}")))?;

    let message_id = tx.last_insert_rowid();

    tx.execute(
        "DELETE FROM upload_sessions WHERE upload_id = ?1",
        params![payload.upload_id],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("清理上传会话失败: {e}")))?;
    tx.execute(
        "DELETE FROM upload_chunks WHERE upload_id = ?1",
        params![payload.upload_id],
    )
    .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("清理上传分片失败: {e}")))?;

    bump_messages_revision(&tx, &auth.user_id)?;

    let dto = {
        let mut stmt = tx
            .prepare("SELECT * FROM messages WHERE id = ?1")
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("查询失败: {e}")))?;
        stmt.query_row(params![message_id], row_to_dto)
            .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "消息不存在"))?
    };

    tx.commit()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("提交事务失败: {e}")))?;

    Ok(Json(dto))
}

async fn cancel_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UploadCancelRequest>,
) -> Result<Json<UploadCancelResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    let conn = open_conn(&state.db_path)?;
    let temp_path: Option<String> = conn
        .query_row(
            "SELECT temp_path FROM upload_sessions WHERE upload_id = ?1 AND user_id = ?2",
            params![payload.upload_id, auth.user_id],
            |row| row.get::<_, String>(0),
        )
        .ok();

    if let Some(path) = temp_path {
        conn.execute(
            "DELETE FROM upload_sessions WHERE upload_id = ?1",
            params![payload.upload_id],
        )
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("删除会话失败: {e}")))?;
        conn.execute(
            "DELETE FROM upload_chunks WHERE upload_id = ?1",
            params![payload.upload_id],
        )
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("删除分片失败: {e}")))?;
        let _ = fs::remove_file(path).await;
        return Ok(Json(UploadCancelResponse { cancelled: true }));
    }

    Ok(Json(UploadCancelResponse { cancelled: false }))
}

async fn delete_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>, AppError> {
    let auth = require_auth(&headers, &state).await?;

    let mut ids: Vec<i64> = payload.ids.into_iter().filter(|v| *v > 0).collect();
    ids.sort_unstable();
    ids.dedup();

    if ids.is_empty() {
        return Ok(Json(DeleteResponse { deleted: 0 }));
    }

    let placeholders = vec!["?"; ids.len()].join(",");
    let sql_find = format!("SELECT file_id FROM messages WHERE user_id = ?1 AND id IN ({placeholders})");
    let sql_del = format!("DELETE FROM messages WHERE user_id = ?1 AND id IN ({placeholders})");

    let mut conn = open_conn(&state.db_path)?;

    let file_ids: Vec<String> = {
        let mut stmt = conn
            .prepare(&sql_find)
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("查询失败: {e}")))?;
        let mut rows = stmt
            .query(rusqlite::params_from_iter(std::iter::once(auth.user_id.clone()).chain(ids.iter().map(|id| id.to_string()))))
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("查询失败: {e}")))?;

        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取失败: {e}")))?
        {
            let fid: Option<String> = row
                .get(0)
                .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取失败: {e}")))?;
            if let Some(v) = fid {
                out.push(v);
            }
        }
        out
    };

    for fid in &file_ids {
        let path = state.files_dir.join(fid);
        if path.exists() {
            fs::remove_file(&path)
                .await
                .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("删除文件失败: {e}")))?;
        }
    }

    let tx = conn
        .transaction()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("开启事务失败: {e}")))?;
    if !file_ids.is_empty() {
        let progress_placeholders = vec!["?"; file_ids.len()].join(",");
        let progress_sql = format!("DELETE FROM video_progress WHERE file_id IN ({progress_placeholders})");
        tx.execute(&progress_sql, rusqlite::params_from_iter(file_ids.iter()))
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("清理视频进度失败: {e}")))?;
    }
    let text_progress_placeholders = vec!["?"; ids.len()].join(",");
    let text_progress_sql = format!("DELETE FROM text_progress WHERE message_id IN ({text_progress_placeholders})");
    tx.execute(&text_progress_sql, rusqlite::params_from_iter(ids.iter().copied()))
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("清理文本进度失败: {e}")))?;

    let deleted = tx
        .execute(&sql_del, rusqlite::params_from_iter(std::iter::once(auth.user_id.clone()).chain(ids.iter().map(|id| id.to_string()))))
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("删除失败: {e}")))?;

    if deleted > 0 {
        bump_messages_revision(&tx, &auth.user_id)?;
    }
    tx.commit()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("提交事务失败: {e}")))?;

    Ok(Json(DeleteResponse { deleted }))
}

async fn direct_file(
    State(state): State<AppState>,
    AxumPath(path): AxumPath<FileRoutePath>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let auth = require_auth(&headers, &state).await?;
    let file_id = path.file_id;
    let _display_name = path.display_name;

    let (file_name, mime_type): (String, String) = {
        let conn = open_conn(&state.db_path)?;
        let mut stmt = conn
            .prepare("SELECT file_name, mime_type FROM messages WHERE file_id = ?1 AND user_id = ?2")
            .map_err(|e| {
                AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("查询失败: {e}"))
            })?;
        stmt.query_row(params![file_id, auth.user_id], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?
                    .unwrap_or_else(|| "file".to_string()),
                row.get::<_, Option<String>>(1)?
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
            ))
        })
        .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "文件不存在"))?
    };

    let path = state.files_dir.join(&file_id);
    let mut file = fs::File::open(&path)
        .await
        .map_err(|_| AppError::new(StatusCode::NOT_FOUND, "文件不存在"))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取文件信息失败: {e}")))?;
    let total_size = metadata.len();

    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|v| parse_range_header(v, total_size))
        .transpose()?
        .flatten();

    let (start, end, status) = match range {
        Some((start, end)) => (start, end, StatusCode::PARTIAL_CONTENT),
        None => (0, total_size.saturating_sub(1), StatusCode::OK),
    };

    let length = if total_size == 0 { 0 } else { end - start + 1 };
    if length > 0 {
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("定位文件失败: {e}")))?;
    }

    let stream = ReaderStream::new(file.take(length));
    let body = Body::from_stream(stream);
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let headers = resp.headers_mut();

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&mime_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    if status == StatusCode::PARTIAL_CONTENT {
        let content_range = format!("bytes {start}-{end}/{total_size}");
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&content_range)
                .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
        );
    }

    if query.get("download").map(String::as_str) == Some("1") {
        let dispo = format!("attachment; filename=\"{}\"", file_name.replace('"', ""));
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&dispo)
                .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
        );
    }

    Ok(resp)
}

async fn restart_service(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RestartResponse>, AppError> {
    let _auth = require_auth(&headers, &state).await?;

    if !state.startup_config.allow_web_restart {
        return Err(AppError::new(
            StatusCode::FORBIDDEN,
            "已禁用网页重启，请设置 FASTFILE_ALLOW_WEB_RESTART=1 并重启服务",
        ));
    }

    if env::var_os("INVOCATION_ID").is_none() {
        return Err(AppError::new(
            StatusCode::CONFLICT,
            "当前非 systemd 托管环境。为避免重启后拉不起来，拒绝网页重启",
        ));
    }

    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(800)).await;
        std::process::exit(0);
    });

    Ok(Json(RestartResponse {
        accepted: true,
        message: "重启请求已接受，服务即将重启".to_string(),
    }))
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("启动失败: {}", e.message);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), AppError> {
    let base_dir = env::current_dir()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("读取目录失败: {e}")))?;
    let config_path = env::var("FASTFILE_CONFIG_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| base_dir.join("fastfile.env"));
    let file_map = load_config_map(&config_path);

    let storage_root = file_map
        .get("FASTFILE_STORAGE")
        .map(PathBuf::from)
        .or_else(|| env::var("FASTFILE_STORAGE").ok().map(PathBuf::from))
        .unwrap_or_else(|| base_dir.join("storage"));
    let port = file_map
        .get("FASTFILE_PORT")
        .and_then(|v| v.parse::<u16>().ok())
        .or_else(|| env::var("FASTFILE_PORT").ok().and_then(|v| v.parse::<u16>().ok()))
        .unwrap_or(21_443);
    let allow_web_restart = file_map
        .get("FASTFILE_ALLOW_WEB_RESTART")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .or_else(|| {
            env::var("FASTFILE_ALLOW_WEB_RESTART")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        })
        .unwrap_or(true);
    let files_dir = storage_root.join("files");
    let temp_dir = storage_root.join("tmp");
    let db_path = storage_root.join("messages.db");

    let initial_runtime_config = load_runtime_config(&config_path)?;
    let primary_user_id = initial_runtime_config.primary_user_id().to_string();
    let runtime_config = Arc::new(RwLock::new(initial_runtime_config));

    init_storage(
        &storage_root,
        &files_dir,
        &temp_dir,
        &db_path,
        &primary_user_id,
    )?;

    let state = AppState {
        db_path,
        files_dir,
        temp_dir,
        runtime_config: runtime_config.clone(),
        startup_config: StartupConfig { allow_web_restart },
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            match load_runtime_config(&config_path) {
                Ok(cfg) => {
                    let mut guard = runtime_config.write().await;
                    *guard = cfg;
                }
                Err(err) => {
                    eprintln!("配置热加载失败: {}", err.message);
                }
            }
        }
    });

    let app = Router::new()
        .route("/", get(index_page))
        .route("/api/healthz", get(healthz))
        .route("/api/public-config", get(public_config))
        .route("/api/auth", post(auth))
        .route("/api/logout", post(logout))
        .route("/api/ui-state", get(get_ui_state).put(update_ui_state))
        .route("/api/ui-state/reset", post(reset_ui_state))
        .route("/api/video-progress/:file_id", get(get_video_progress).put(update_video_progress))
        .route("/api/text-progress/:message_id", get(get_text_progress).put(update_text_progress))
        .route("/api/messages", get(list_messages).delete(delete_messages))
        .route("/api/messages/text", post(create_text_message))
        .route("/api/messages/file", post(create_file_message))
        .route("/api/uploads/init", post(init_upload))
        .route("/api/uploads/chunk", post(upload_chunk))
        .route("/api/uploads/complete", post(complete_upload))
        .route("/api/uploads/cancel", post(cancel_upload))
        .route("/api/admin/restart", post(restart_service))
        .route("/f/:file_id/*display_name", get(direct_file))
        .layer(DefaultBodyLimit::disable())
        .layer(middleware::from_fn(no_cache_middleware))
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("地址解析失败: {e}")))?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("监听失败: {e}")))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("服务异常: {e}")))
}

fn load_runtime_config(config_path: &Path) -> Result<RuntimeConfig, AppError> {
    let file_map = load_config_map(config_path);

    let password_raw = file_map
        .get("FASTFILE_PASSWORD")
        .cloned()
        .or_else(|| env::var("FASTFILE_PASSWORD").ok())
        .unwrap_or_default();

    let users = parse_runtime_users(&password_raw);
    if users.is_empty() {
        return Err(AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "缺少 FASTFILE_PASSWORD，请在 fastfile.env 或环境变量中显式设置登录密码",
        ));
    }

    let session_ttl_seconds = file_map
        .get("FASTFILE_SESSION_TTL_SECONDS")
        .and_then(|v| v.parse::<i64>().ok())
        .or_else(|| {
            env::var("FASTFILE_SESSION_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
        })
        .filter(|v| *v > 0)
        .unwrap_or(86_400);

    let upload_limit_raw = file_map
        .get("FASTFILE_SINGLE_UPLOAD_LIMIT")
        .cloned()
        .or_else(|| env::var("FASTFILE_SINGLE_UPLOAD_LIMIT").ok())
        .unwrap_or_else(|| "5GB".to_string());
    let (single_upload_limit_bytes, single_upload_limit_label) = parse_upload_limit_spec(&upload_limit_raw)?;

    Ok(RuntimeConfig {
        users,
        session_ttl_seconds,
        single_upload_limit_bytes,
        single_upload_limit_label,
    })
}

fn load_config_map(config_path: &Path) -> HashMap<String, String> {
    let mut file_map: HashMap<String, String> = HashMap::new();
    if let Ok(iter) = dotenvy::from_path_iter(config_path) {
        for (k, v) in iter.flatten() {
            file_map.insert(k, v);
        }
    }
    file_map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_storage_root(name: &str) -> PathBuf {
        let unique = format!("fastfile-test-{name}-{}", create_token());
        env::temp_dir().join(unique)
    }

    #[test]
    fn init_storage_creates_message_revision_for_empty_database() {
        let storage_root = temp_storage_root("empty-revision");
        let files_dir = storage_root.join("files");
        let temp_dir = storage_root.join("tmp");
        let db_path = storage_root.join("messages.db");

        init_storage(&storage_root, &files_dir, &temp_dir, &db_path, "u_test").unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let revision: String = conn
            .query_row(
                "SELECT value FROM app_meta WHERE key = ?1",
                params![messages_revision_meta_key("u_test")],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revision, "0");

        let _ = std::fs::remove_dir_all(storage_root);
    }

    #[test]
    fn init_storage_backfills_message_revision_from_existing_messages() {
        let storage_root = temp_storage_root("existing-revision");
        std::fs::create_dir_all(&storage_root).unwrap();
        let files_dir = storage_root.join("files");
        let temp_dir = storage_root.join("tmp");
        let db_path = storage_root.join("messages.db");

        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                text_content TEXT,
                file_id TEXT UNIQUE,
                file_name TEXT,
                file_size INTEGER,
                mime_type TEXT,
                created_at TEXT NOT NULL
            );
            INSERT INTO messages (kind, text_content, created_at) VALUES ('text', 'first', '2024-01-01T00:00:00Z');
            INSERT INTO messages (kind, text_content, created_at) VALUES ('text', 'second', '2024-01-01T00:00:01Z');
            ",
        )
        .unwrap();
        drop(conn);

        init_storage(&storage_root, &files_dir, &temp_dir, &db_path, "u_test").unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let revision: String = conn
            .query_row(
                "SELECT value FROM app_meta WHERE key = ?1",
                params![messages_revision_meta_key("u_test")],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revision, "2");

        let user_id: String = conn
            .query_row("SELECT user_id FROM messages WHERE id = 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(user_id, "u_test");

        let _ = std::fs::remove_dir_all(storage_root);
    }

    #[test]
    fn parse_runtime_users_supports_multiple_passwords() {
        let users = parse_runtime_users("alpha, beta ,alpha,,gamma");
        assert_eq!(users.len(), 3);
        assert_eq!(users[0].password, "alpha");
        assert_eq!(users[1].password, "beta");
        assert_eq!(users[2].password, "gamma");
    }

    #[test]
    fn parse_upload_limit_spec_supports_mb_gb_and_decimals() {
        let (bytes_gb, label_gb) = parse_upload_limit_spec("5.121315GB").unwrap();
        assert_eq!(label_gb, "5.121315 GB");
        assert!(bytes_gb > 5_i64 * 1024 * 1024 * 1024);

        let (bytes_mb, label_mb) = parse_upload_limit_spec("512MB").unwrap();
        assert_eq!(label_mb, "512 MB");
        assert_eq!(bytes_mb, 512_i64 * 1024 * 1024);
    }
}
