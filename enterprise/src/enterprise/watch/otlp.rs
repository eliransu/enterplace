//! OTLP over HTTP as Claude Code sends it: an `ExportMetricsServiceRequest` or `ExportLogsServiceRequest`, as
//! protobuf (its default) or JSON, read into the same points and events. Only what watch mode reads is decoded: sums
//! of number points, and log records with scalar attributes. Field numbers are those of opentelemetry-proto 1.x.
//!
//! The protobuf reader is written here: the build has no protobuf library, and the two messages need a few dozen
//! lines of wire format, not a code generator.

use std::collections::BTreeMap;

use serde_json::Value;

/// A record's attributes over its resource's: string, number or bool. Lists and maps are not read.
pub type Attrs = BTreeMap<String, Value>;

/// One point of a sum.
#[derive(Debug, PartialEq)]
pub struct Point {
    pub metric: String,
    /// Cumulative temporality: the value is the total since `start_ns`, not what the interval added.
    pub cumulative: bool,
    pub start_ns: u64,
    pub time_ns: u64,
    pub value: f64,
    pub attrs: Attrs,
}

/// One log record.
#[derive(Debug, PartialEq)]
pub struct Event {
    pub time_ns: u64,
    /// The body when it is a string: Claude Code writes the event's name there.
    pub body: String,
    pub attrs: Attrs,
}

// ---------------------------------------------------------------- JSON

fn u64_of(value: &Value) -> u64 {
    match value {
        Value::String(s) => s.parse().unwrap_or(0),
        v => v.as_u64().unwrap_or(0),
    }
}

fn f64_of(value: &Value) -> Option<f64> {
    match value {
        Value::String(s) => s.parse().ok(),
        v => v.as_f64(),
    }
}

fn json_attrs(list: &Value, into: &mut Attrs) {
    for pair in list.as_array().into_iter().flatten() {
        let (Some(key), Some(value)) = (pair["key"].as_str(), pair["value"].as_object()) else {
            continue;
        };
        let value = if let Some(s) = value.get("stringValue") {
            s.clone()
        } else if let Some(n) = value.get("intValue") {
            // An int64 is a string in OTLP JSON; Claude Code writes a number.
            match n {
                Value::String(s) => s.parse::<i64>().map_or(Value::Null, Value::from),
                n => n.clone(),
            }
        } else if let Some(n) = value.get("doubleValue") {
            n.clone()
        } else if let Some(b) = value.get("boolValue") {
            b.clone()
        } else {
            continue;
        };
        into.insert(key.to_string(), value);
    }
}

fn json_body(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(body).map_err(|err| format!("the body is not JSON ({err})"))
}

pub fn metrics_json(body: &[u8]) -> Result<Vec<Point>, String> {
    let body = json_body(body)?;
    let mut points = Vec::new();
    for resource in body["resourceMetrics"].as_array().into_iter().flatten() {
        let mut shared = Attrs::new();
        json_attrs(&resource["resource"]["attributes"], &mut shared);
        let metrics = resource["scopeMetrics"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|scope| scope["metrics"].as_array().into_iter().flatten());
        for metric in metrics {
            let sum = &metric["sum"];
            let cumulative = match &sum["aggregationTemporality"] {
                Value::String(name) => name.ends_with("CUMULATIVE"),
                n => n.as_u64() == Some(2),
            };
            for point in sum["dataPoints"].as_array().into_iter().flatten() {
                let Some(value) = point
                    .get("asDouble")
                    .or_else(|| point.get("asInt"))
                    .and_then(f64_of)
                else {
                    continue;
                };
                let mut attrs = shared.clone();
                json_attrs(&point["attributes"], &mut attrs);
                points.push(Point {
                    metric: metric["name"].as_str().unwrap_or_default().to_string(),
                    cumulative,
                    start_ns: u64_of(&point["startTimeUnixNano"]),
                    time_ns: u64_of(&point["timeUnixNano"]),
                    value,
                    attrs,
                });
            }
        }
    }
    Ok(points)
}

pub fn logs_json(body: &[u8]) -> Result<Vec<Event>, String> {
    let body = json_body(body)?;
    let mut events = Vec::new();
    for resource in body["resourceLogs"].as_array().into_iter().flatten() {
        let mut shared = Attrs::new();
        json_attrs(&resource["resource"]["attributes"], &mut shared);
        let records = resource["scopeLogs"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|scope| scope["logRecords"].as_array().into_iter().flatten());
        for record in records {
            let mut attrs = shared.clone();
            json_attrs(&record["attributes"], &mut attrs);
            let time = match u64_of(&record["timeUnixNano"]) {
                0 => u64_of(&record["observedTimeUnixNano"]),
                t => t,
            };
            events.push(Event {
                time_ns: time,
                body: record["body"]["stringValue"]
                    .as_str()
                    .or_else(|| record["eventName"].as_str())
                    .unwrap_or_default()
                    .to_string(),
                attrs,
            });
        }
    }
    Ok(events)
}

// ---------------------------------------------------------------- protobuf

enum Field<'a> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'a [u8]),
}

/// The fields of one message, in order. Ends at the first error, which `fields` reports.
struct Reader<'a> {
    rest: &'a [u8],
}

const CUT: &str = "the protobuf message is cut short or not protobuf";

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (byte, rest) = self.rest.split_first().ok_or(CUT)?;
            self.rest = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(CUT.into())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if n > self.rest.len() {
            return Err(CUT.into());
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(head)
    }

    fn next(&mut self) -> Result<Option<(u64, Field<'a>)>, String> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let field = match tag & 7 {
            0 => Field::Varint(self.varint()?),
            1 => {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(self.take(8)?);
                Field::Fixed64(u64::from_le_bytes(bytes))
            }
            2 => {
                let n = usize::try_from(self.varint()?).map_err(|_| CUT)?;
                Field::Bytes(self.take(n)?)
            }
            // A fixed32: no field read here has one, so it is stepped over.
            5 => {
                self.take(4)?;
                Field::Varint(0)
            }
            _ => return Err(CUT.into()),
        };
        Ok(Some((tag >> 3, field)))
    }
}

/// Calls `each` with every field of `message`.
fn fields<'a>(
    message: &'a [u8],
    mut each: impl FnMut(u64, Field<'a>) -> Result<(), String>,
) -> Result<(), String> {
    let mut reader = Reader { rest: message };
    while let Some((number, field)) = reader.next()? {
        each(number, field)?;
    }
    Ok(())
}

fn string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// An `AnyValue`: string 1, bool 2, int 3, double 4. A list, a map or bytes is `None`.
fn any_value(message: &[u8]) -> Result<Option<Value>, String> {
    let mut value = None;
    fields(message, |number, field| {
        value = match (number, field) {
            (1, Field::Bytes(s)) => Some(Value::from(string(s))),
            (2, Field::Varint(b)) => Some(Value::from(b != 0)),
            // An int64 travels as its two's complement; the cast reads it back.
            (3, Field::Varint(n)) => Some(Value::from(n as i64)),
            (4, Field::Fixed64(bits)) => Some(Value::from(f64::from_bits(bits))),
            _ => return Ok(()),
        };
        Ok(())
    })?;
    Ok(value)
}

/// A `KeyValue` (key 1, value 2) into `into`.
fn key_value(message: &[u8], into: &mut Attrs) -> Result<(), String> {
    let (mut key, mut value) = (String::new(), None);
    fields(message, |number, field| {
        match (number, field) {
            (1, Field::Bytes(k)) => key = string(k),
            (2, Field::Bytes(v)) => value = any_value(v)?,
            _ => {}
        }
        Ok(())
    })?;
    if let Some(value) = value {
        into.insert(key, value);
    }
    Ok(())
}

/// A `Resource`: attributes 1.
fn resource(message: &[u8]) -> Result<Attrs, String> {
    let mut attrs = Attrs::new();
    fields(message, |number, field| match (number, field) {
        (1, Field::Bytes(pair)) => key_value(pair, &mut attrs),
        _ => Ok(()),
    })?;
    Ok(attrs)
}

/// The messages in field `number` of `message`.
fn nested(message: &[u8], number: u64) -> Result<Vec<&[u8]>, String> {
    let mut found = Vec::new();
    fields(message, |n, field| {
        if let (true, Field::Bytes(inner)) = (n == number, field) {
            found.push(inner);
        }
        Ok(())
    })?;
    Ok(found)
}

/// A resource block: its attributes and its scope blocks.
type Block<'a> = (Attrs, Vec<&'a [u8]>);

/// Each resource block of an export (field 1), as its attributes and its scope blocks (field 2).
fn resources(body: &[u8]) -> Result<Vec<Block<'_>>, String> {
    let mut found = Vec::new();
    for block in nested(body, 1)? {
        let shared = match nested(block, 1)?.first() {
            Some(r) => resource(r)?,
            None => Attrs::new(),
        };
        found.push((shared, nested(block, 2)?));
    }
    Ok(found)
}

pub fn metrics_proto(body: &[u8]) -> Result<Vec<Point>, String> {
    let mut points = Vec::new();
    for (shared, scopes) in resources(body)? {
        for scope in scopes {
            // ScopeMetrics: metrics 2. Metric: name 1, sum 7.
            for metric in nested(scope, 2)? {
                let name = nested(metric, 1)?.first().map(|n| string(n));
                let (Some(name), Some(sum)) = (name, nested(metric, 7)?.first().copied()) else {
                    continue;
                };
                // Sum: data points 1, aggregation temporality 2 (2 is cumulative).
                let mut cumulative = false;
                fields(sum, |number, field| {
                    if let (2, Field::Varint(t)) = (number, field) {
                        cumulative = t == 2;
                    }
                    Ok(())
                })?;
                for point in nested(sum, 1)? {
                    // NumberDataPoint: start 2, time 3, as_double 4, as_int 6, attributes 7.
                    let (mut start, mut time, mut value) = (0, 0, None);
                    let mut attrs = shared.clone();
                    fields(point, |number, field| {
                        match (number, field) {
                            (2, Field::Fixed64(t)) => start = t,
                            (3, Field::Fixed64(t)) => time = t,
                            (4, Field::Fixed64(bits)) => value = Some(f64::from_bits(bits)),
                            (6, Field::Fixed64(n)) => value = Some(n as i64 as f64),
                            (7, Field::Bytes(pair)) => key_value(pair, &mut attrs)?,
                            _ => {}
                        }
                        Ok(())
                    })?;
                    if let Some(value) = value {
                        points.push(Point {
                            metric: name.clone(),
                            cumulative,
                            start_ns: start,
                            time_ns: time,
                            value,
                            attrs,
                        });
                    }
                }
            }
        }
    }
    Ok(points)
}

pub fn logs_proto(body: &[u8]) -> Result<Vec<Event>, String> {
    let mut events = Vec::new();
    for (shared, scopes) in resources(body)? {
        for scope in scopes {
            // ScopeLogs: log records 2. LogRecord: time 1, body 5, attributes 6, observed time 11, event name 12.
            for record in nested(scope, 2)? {
                let (mut time, mut observed) = (0, 0);
                let (mut body, mut name) = (None, String::new());
                let mut attrs = shared.clone();
                fields(record, |number, field| {
                    match (number, field) {
                        (1, Field::Fixed64(t)) => time = t,
                        (11, Field::Fixed64(t)) => observed = t,
                        (5, Field::Bytes(value)) => body = any_value(value)?,
                        (6, Field::Bytes(pair)) => key_value(pair, &mut attrs)?,
                        (12, Field::Bytes(n)) => name = string(n),
                        _ => {}
                    }
                    Ok(())
                })?;
                events.push(Event {
                    time_ns: if time == 0 { observed } else { time },
                    body: match body {
                        Some(Value::String(text)) => text,
                        _ => name,
                    },
                    attrs,
                });
            }
        }
    }
    Ok(events)
}
