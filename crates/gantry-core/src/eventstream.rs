//! Amazon Bedrock's streamed answers arrive as an AWS event stream (`application/vnd.amazon.eventstream`).
//! [`BedrockToSse`] turns one into the Anthropic server-sent events a messages client such as Claude Code reads.
//!
//! Formats as documented on 2026-11-13:
//! - <https://smithy.io/2.0/aws/amazon-eventstream.html> (framing, header types, message types)
//! - <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModelWithResponseStream.html>
//!   (a `chunk` event holds `{"bytes": <base64 of one Anthropic stream event>}`; exceptions are named events)

use serde_json::{Value, json};

/// Prelude (lengths and their CRC) plus the message CRC.
const OVERHEAD: usize = 16;
/// 24 MiB of payload and 128 KiB of headers, the most the format allows, plus the overhead.
const MAX_MESSAGE: usize = 24 * 1024 * 1024 + 128 * 1024 + OVERHEAD;

/// CRC-32 (IEEE 802.3, as zlib computes it), which the format uses for both of its checksums.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Standard base64 with padding, as Bedrock encodes each chunk.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// One message of the stream: its string headers and its payload.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub headers: Vec<(String, String)>,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn be32(bytes: &[u8]) -> usize {
    let mut n = 0usize;
    for &b in bytes.iter().take(4) {
        n = (n << 8) | usize::from(b);
    }
    n
}

/// Reads messages out of bytes that arrive in any split.
#[derive(Debug, Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    /// Every whole message in what has arrived so far. A damaged message is an error: the stream cannot be trusted past it.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Message>, String> {
        self.buffer.extend_from_slice(bytes);
        let mut messages = Vec::new();
        let mut start = 0;
        while self.buffer.len() - start >= 12 {
            let frame = &self.buffer[start..];
            if crc32(&frame[..8]) as usize != be32(&frame[8..12]) {
                return Err(
                    "the provider's event stream is damaged: a message prelude fails its checksum."
                        .into(),
                );
            }
            let total = be32(&frame[..4]);
            let headers_len = be32(&frame[4..8]);
            if !(OVERHEAD..=MAX_MESSAGE).contains(&total) || headers_len > total - OVERHEAD {
                return Err(
                    "the provider's event stream is damaged: a message has an impossible length."
                        .into(),
                );
            }
            if frame.len() < total {
                break;
            }
            if crc32(&frame[..total - 4]) as usize != be32(&frame[total - 4..total]) {
                return Err(
                    "the provider's event stream is damaged: a message fails its checksum.".into(),
                );
            }
            let headers = parse_headers(&frame[12..12 + headers_len])?;
            messages.push(Message {
                headers,
                payload: frame[12 + headers_len..total - 4].to_vec(),
            });
            start += total;
        }
        self.buffer.drain(..start);
        Ok(messages)
    }

    /// Whether the stream ended between messages, as a whole stream does.
    pub fn is_clean(&self) -> bool {
        self.buffer.is_empty()
    }
}

fn parse_headers(mut bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let bad =
        || "the provider's event stream is damaged: a message header is cut short.".to_string();
    let mut headers = Vec::new();
    while let Some((&name_len, rest)) = bytes.split_first() {
        let name_len = usize::from(name_len);
        let name = rest.get(..name_len).ok_or_else(bad)?;
        let (&kind, rest) = rest
            .get(name_len..)
            .ok_or_else(bad)?
            .split_first()
            .ok_or_else(bad)?;
        // Fixed sizes of types 0 to 9; 6 and 7 carry their own two-byte length.
        let size = match kind {
            0 | 1 => 0,
            2 => 1,
            3 => 2,
            4 => 4,
            5 | 8 => 8,
            9 => 16,
            6 | 7 => {
                let len = rest.get(..2).ok_or_else(bad)?;
                2 + (usize::from(len[0]) << 8 | usize::from(len[1]))
            }
            _ => {
                return Err(
                    "the provider's event stream is damaged: a header has an unknown type.".into(),
                );
            }
        };
        let value = rest.get(..size).ok_or_else(bad)?;
        if kind == 7 {
            headers.push((
                String::from_utf8_lossy(name).into_owned(),
                String::from_utf8_lossy(&value[2..]).into_owned(),
            ));
        }
        bytes = &rest[size..];
    }
    Ok(headers)
}

/// The Anthropic error type for a Bedrock exception, so a client retries or stops as it would with Anthropic.
fn anthropic_error_type(exception: &str) -> &'static str {
    match exception {
        "throttlingException" | "ThrottlingException" => "rate_limit_error",
        "validationException" | "ValidationException" => "invalid_request_error",
        "serviceUnavailableException" | "ServiceUnavailableException" => "overloaded_error",
        "modelTimeoutException" | "ModelTimeoutException" => "timeout_error",
        "AccessDeniedException" => "permission_error",
        "ResourceNotFoundException" => "not_found_error",
        _ => "api_error",
    }
}

/// An Anthropic error body for a Bedrock error, from its type (the `x-amzn-ErrorType` header or the
/// exception name) and its JSON body, which holds a `message`.
pub fn anthropic_error(exception: &str, body: &[u8]) -> Value {
    // The header reads `ThrottlingException:http://internal.amazon.com/...`; only the name counts.
    let name = exception.split(':').next().unwrap_or_default();
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("Message"))
                .and_then(Value::as_str)
                .map(String::from)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    let message = if name.is_empty() {
        format!("Amazon Bedrock: {message}")
    } else {
        format!("Amazon Bedrock {name}: {message}")
    };
    json!({"type": "error", "error": {"type": anthropic_error_type(name), "message": message}})
}

/// Turns Bedrock's event stream into Anthropic server-sent events as the bytes arrive.
#[derive(Debug, Default)]
pub struct BedrockToSse {
    decoder: Decoder,
}

impl BedrockToSse {
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for message in self.decoder.feed(bytes)? {
            let event = match message.header(":message-type") {
                Some("event") if message.header(":event-type") == Some("chunk") => {
                    let chunk: Value = serde_json::from_slice(&message.payload)
                        .map_err(|_| "the provider sent a chunk that is not JSON.".to_string())?;
                    let decoded = chunk["bytes"]
                        .as_str()
                        .and_then(base64_decode)
                        .ok_or("the provider sent a chunk without base64 bytes.")?;
                    serde_json::from_slice::<Value>(&decoded).map_err(|_| {
                        "the provider sent a chunk that holds no JSON event.".to_string()
                    })?
                }
                // Events Gantry does not know carry nothing a messages client reads.
                Some("event") => continue,
                Some("exception") => anthropic_error(
                    message.header(":exception-type").unwrap_or_default(),
                    &message.payload,
                ),
                _ => anthropic_error(
                    message.header(":error-code").unwrap_or_default(),
                    message
                        .header(":error-message")
                        .unwrap_or_default()
                        .as_bytes(),
                ),
            };
            let name = event["type"].as_str().unwrap_or("message");
            out.extend_from_slice(format!("event: {name}\ndata: {event}\n\n").as_bytes());
        }
        Ok(out)
    }

    pub fn finish(&mut self) -> Result<Vec<u8>, String> {
        if self.decoder.is_clean() {
            Ok(Vec::new())
        } else {
            Err("the provider's event stream ended in the middle of a message.".into())
        }
    }
}

/// Encodes one message, for tests and mock providers.
pub fn encode(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let mut head = Vec::new();
    for (name, value) in headers {
        head.push(name.len() as u8);
        head.extend_from_slice(name.as_bytes());
        head.push(7);
        head.extend_from_slice(&(value.len() as u16).to_be_bytes());
        head.extend_from_slice(value.as_bytes());
    }
    let total = (OVERHEAD + head.len() + payload.len()) as u32;
    let mut out = Vec::new();
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&(head.len() as u32).to_be_bytes());
    let prelude = crc32(&out);
    out.extend_from_slice(&prelude.to_be_bytes());
    out.extend_from_slice(&head);
    out.extend_from_slice(payload);
    let all = crc32(&out);
    out.extend_from_slice(&all.to_be_bytes());
    out
}

/// A Bedrock `chunk` event holding one Anthropic stream event, for tests and mock providers.
pub fn chunk(event: &Value) -> Vec<u8> {
    let payload = json!({ "bytes": base64_encode(event.to_string().as_bytes()) });
    encode(
        &[
            (":message-type", "event"),
            (":event-type", "chunk"),
            (":content-type", "application/json"),
        ],
        payload.to_string().as_bytes(),
    )
}

fn base64_encode(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for group in bytes.chunks(3) {
        let n = group
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= group.len() {
                out.push(char::from(ABC[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn crc32_matches_the_standard_check_value() {
        // The check value of CRC-32/ISO-HDLC, the one zlib computes.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn base64_round_trips() {
        for text in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(
                base64_decode(&base64_encode(text.as_bytes())),
                Some(text.as_bytes().to_vec())
            );
        }
        assert_eq!(base64_decode("Zm9vYmFy"), Some(b"foobar".to_vec()));
        assert_eq!(base64_decode("Zm9v!"), None);
    }

    #[test]
    fn a_stream_split_anywhere_becomes_anthropic_events() -> TestResult {
        let start = json!({"type":"message_start","message":{"id":"msg_1","model":"m"}});
        let delta = json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}});
        let stop =
            json!({"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":3}});
        let stream = [chunk(&start), chunk(&delta), chunk(&stop)].concat();
        for split in [1, 7, 13, stream.len()] {
            let mut sse = BedrockToSse::default();
            let mut out = Vec::new();
            for part in stream.chunks(split) {
                out.extend(sse.feed(part)?);
            }
            out.extend(sse.finish()?);
            let text = String::from_utf8(out)?;
            assert!(
                text.starts_with("event: message_start\ndata: {\"type\":\"message_start\""),
                "{text}"
            );
            assert!(text.contains("event: content_block_delta\n"), "{text}");
            assert!(text.contains("\"text\":\"Hi\""), "{text}");
            assert!(text.ends_with("}\n\n"), "{text}");
            assert_eq!(text.matches("event: ").count(), 3);
        }
        Ok(())
    }

    #[test]
    fn an_exception_becomes_an_anthropic_error_event() -> TestResult {
        let throttled = encode(
            &[
                (":message-type", "exception"),
                (":exception-type", "throttlingException"),
            ],
            br#"{"message":"Too many requests"}"#,
        );
        let mut sse = BedrockToSse::default();
        let text = String::from_utf8(sse.feed(&throttled)?)?;
        assert!(text.starts_with("event: error\n"), "{text}");
        assert!(text.contains("rate_limit_error"), "{text}");
        assert!(text.contains("Too many requests"), "{text}");
        Ok(())
    }

    #[test]
    fn a_damaged_or_cut_stream_is_an_error() -> TestResult {
        let mut frame = chunk(&json!({"type":"ping"}));
        let mut sse = BedrockToSse::default();
        sse.feed(&frame[..frame.len() - 3])?;
        assert!(sse.finish().is_err());
        let last = frame.len() - 6;
        frame[last] ^= 1;
        assert!(BedrockToSse::default().feed(&frame).is_err());
        Ok(())
    }

    #[test]
    fn a_bedrock_error_body_becomes_an_anthropic_error() {
        let error = anthropic_error(
            "ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/",
            br#"{"message":"max_tokens is required"}"#,
        );
        assert_eq!(error["type"], "error");
        assert_eq!(error["error"]["type"], "invalid_request_error");
        assert_eq!(
            error["error"]["message"],
            "Amazon Bedrock ValidationException: max_tokens is required"
        );
    }
}
