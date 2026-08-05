//! A deliberately small HTTP/1.1 client and server, over `std::net`, with no async runtime.
//!
//! This exists so the conformance suite has no dependency on the transport stack of the thing it is
//! judging, boots in milliseconds, and is trivially auditable — a harness that can itself be wrong in
//! interesting ways is worse than no harness. It speaks exactly the subset of HTTP the contract needs:
//! one JSON POST out (the dispatch), and GET/POST in (the source fetch and the callback).
//!
//! Known limits, stated rather than hidden:
//! * `http://` only. Everything the suite talks to is loopback, and TLS would add a dependency whose
//!   failure modes we would then have to debug inside a test failure. Production endpoints are HTTPS
//!   (spec §8); pointing this suite at one is out of scope — put it behind a local terminator.
//! * Request bodies are read from `Content-Length` or `Transfer-Encoding: chunked`; nothing else.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// How long we will wait for a peer to produce a status line and headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
/// How long we will keep draining a response body that declared no length.
///
/// `fake-ci.py` (and any `BaseHTTPRequestHandler`) answers a dispatch with an HTTP/1.0 response that
/// has no `Content-Length`: the body is terminated by connection close, and the connection does not
/// close until the handler returns — which, for a CI that runs the job inline, is *after* the whole
/// job. Blocking on EOF there would turn "acknowledge promptly" into "acknowledge eventually" and
/// deadlock the suite's own timing assertions, so an unlengthed body gets this grace period and
/// whatever arrived in it.
const UNLENGTHED_BODY_GRACE: Duration = Duration::from_millis(400);

// ── Messages ─────────────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    /// The request target exactly as it came off the wire, path and query together.
    pub target: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Case-insensitive header lookup (RFC 9110 §5.1: field names are case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// A one-line rendering for failure messages: `GET /source/ab12/tar?x=1`.
    pub fn line(&self) -> String {
        format!("{} {}", self.method, self.target)
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        HttpResponse {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.into().into_bytes(),
        }
    }

    pub fn empty(status: u16) -> Self {
        HttpResponse { status, headers: Vec::new(), body: Vec::new() }
    }

    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        HttpResponse {
            status,
            headers: vec![("Content-Type".into(), content_type.into())],
            body,
        }
    }

    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

// ── Client ───────────────────────────────────────────────────────────────────────────────────────

/// POST `body` to `url` with `headers`. Returns the parsed response.
pub fn post(url: &str, headers: &[(&str, &str)], body: &[u8]) -> std::io::Result<HttpResponse> {
    request("POST", url, headers, Some(body))
}

/// GET `url`. Used by the suite's own fidelity checks, not by the contract.
pub fn get(url: &str, headers: &[(&str, &str)]) -> std::io::Result<HttpResponse> {
    request("GET", url, headers, None)
}

fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> std::io::Result<HttpResponse> {
    let (host, port, target) = split_url(url)?;
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not connect to {addr} (is the CI endpoint under test running?): {e}"),
        )
    })?;
    stream.set_read_timeout(Some(HEADER_TIMEOUT))?;
    stream.set_write_timeout(Some(HEADER_TIMEOUT))?;

    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    // Always frame the body with Content-Length: the reference CI reads it directly
    // (`self.headers["Content-Length"]`) and would KeyError on a chunked request.
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.map_or(0, |b| b.len())));
    stream.write_all(head.as_bytes())?;
    if let Some(b) = body {
        stream.write_all(b)?;
    }
    stream.flush()?;

    read_response(stream)
}

fn read_response(stream: TcpStream) -> std::io::Result<HttpResponse> {
    let mut reader = BufReader::new(stream);
    let start = read_line(&mut reader)?;
    let status: u16 = start
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidData, format!("malformed status line: {start:?}"))
        })?;
    let headers = read_headers(&mut reader)?;
    let lookup: HashMap<String, String> =
        headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect();

    let body = if lookup
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        read_chunked(&mut reader)?
    } else if let Some(len) = lookup.get("content-length").and_then(|v| v.trim().parse::<usize>().ok())
    {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        // No framing: read what arrives within the grace period rather than waiting for close.
        reader.get_ref().set_read_timeout(Some(UNLENGTHED_BODY_GRACE))?;
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf); // a timeout here is expected, not an error
        buf
    };

    Ok(HttpResponse { status, headers, body })
}

// ── Server ───────────────────────────────────────────────────────────────────────────────────────

/// A running loopback server. Dropping it stops the accept loop.
pub struct Server {
    pub addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
}

impl Server {
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.addr.port())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

/// Bind an ephemeral loopback port and serve `handler` until the returned [`Server`] is dropped.
pub fn spawn<H>(handler: H) -> std::io::Result<Server>
where
    H: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(handler);

    {
        let shutdown = Arc::clone(&shutdown);
        thread::spawn(move || {
            while !shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let handler = Arc::clone(&handler);
                        thread::spawn(move || {
                            let _ = serve_connection(stream, handler);
                        });
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
    }

    Ok(Server { addr, shutdown })
}

fn serve_connection<H>(stream: TcpStream, handler: Arc<H>) -> std::io::Result<()>
where
    H: Fn(HttpRequest) -> HttpResponse + Send + Sync + 'static,
{
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let peer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut writer = peer;

    // Keep-alive: a client (reqwest, curl) may pipeline several requests down one connection.
    loop {
        let request = match read_request(&mut reader)? {
            Some(r) => r,
            None => return Ok(()), // clean EOF
        };
        let wants_close = request
            .header("connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("close"));

        let response = handler(request);
        let mut head = format!("HTTP/1.1 {} {}\r\n", response.status, reason(response.status));
        for (k, v) in &response.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
        if wants_close {
            head.push_str("Connection: close\r\n");
        }
        head.push_str("\r\n");
        writer.write_all(head.as_bytes())?;
        writer.write_all(&response.body)?;
        writer.flush()?;
        if wants_close {
            return Ok(());
        }
    }
}

fn read_request(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<HttpRequest>> {
    let start = match read_line_opt(reader)? {
        Some(l) if !l.trim().is_empty() => l,
        _ => return Ok(None),
    };
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (target.clone(), None),
    };
    let headers = read_headers(reader)?;
    let lookup: HashMap<String, String> =
        headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect();

    let body = if lookup
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        read_chunked(reader)?
    } else if let Some(len) = lookup.get("content-length").and_then(|v| v.trim().parse::<usize>().ok())
    {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        Vec::new()
    };

    Ok(Some(HttpRequest { method, target, path, query, headers, body }))
}

fn read_headers(reader: &mut BufReader<TcpStream>) -> std::io::Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    loop {
        let line = read_line(reader)?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return Ok(headers);
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
}

fn read_chunked(reader: &mut BufReader<TcpStream>) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let size_line = read_line(reader)?;
        let size_hex = size_line.trim().split(';').next().unwrap_or("").trim().to_string();
        let size = usize::from_str_radix(&size_hex, 16)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, format!("bad chunk size: {e}")))?;
        if size == 0 {
            // Consume the trailer section.
            while !read_line(reader)?.trim().is_empty() {}
            return Ok(out);
        }
        let mut buf = vec![0u8; size];
        reader.read_exact(&mut buf)?;
        out.extend_from_slice(&buf);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
}

fn read_line(reader: &mut BufReader<TcpStream>) -> std::io::Result<String> {
    read_line_opt(reader)?
        .ok_or_else(|| std::io::Error::new(ErrorKind::UnexpectedEof, "peer closed mid-message"))
}

fn read_line_opt(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(line))
}

/// `http://host:port/path?query` → `(host, port, target)`.
fn split_url(url: &str) -> std::io::Result<(String, u16, String)> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("the conformance harness speaks http:// only (loopback); got {url:?}"),
        )
    })?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}
