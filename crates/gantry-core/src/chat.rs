//! The canonical chat request: the one shape every provider adapter translates from.
//!
//! It follows the OpenAI chat schema, because that is what most clients send. The request is kept as the
//! JSON object the client sent: field order, explicit nulls, big numbers and unknown fields all survive,
//! so writing it back out changes nothing but whitespace. Typed accessors read the fields Gantry acts on.
//!
//! A request sent on to a provider that speaks the same format is forwarded as its original bytes and
//! never passes through this type. This type is for translating to a provider that speaks another format.

use std::{collections::HashSet, fmt};

use serde::de::{DeserializeSeed, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Why a body is not a chat request. The text names the cause and can be shown to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatError(String);

impl fmt::Display for ChatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ChatError {}

#[derive(Clone, Debug, PartialEq)]
pub struct ChatRequest(Map<String, Value>);

impl ChatRequest {
    /// Reads a request, refusing anything Gantry could not write back out exactly.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ChatError> {
        // Two keys with the same name mean different things to different parsers. Keeping one would be a silent rewrite.
        reject_duplicate_keys(bytes)
            .map_err(|err| ChatError(format!("The request body is not usable JSON: {err}.")))?;
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|err| ChatError(format!("The request body is not JSON: {err}.")))?;
        let Value::Object(fields) = value else {
            return Err(ChatError("The request body must be a JSON object.".into()));
        };
        if !fields.get("model").is_some_and(Value::is_string) {
            return Err(ChatError(
                "The request needs a \"model\" field that is a string.".into(),
            ));
        }
        let Some(Value::Array(messages)) = fields.get("messages") else {
            return Err(ChatError(
                "The request needs a \"messages\" field that is a list.".into(),
            ));
        };
        if !messages
            .iter()
            .all(|m| m.get("role").is_some_and(Value::is_string))
        {
            return Err(ChatError(
                "Every message needs a \"role\" field that is a string.".into(),
            ));
        }
        match fields.get("stream") {
            None | Some(Value::Null | Value::Bool(_)) => {}
            Some(_) => {
                return Err(ChatError(
                    "The \"stream\" field must be true, false or null.".into(),
                ));
            }
        }
        Ok(Self(fields))
    }

    pub fn model(&self) -> &str {
        self.0
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    pub fn messages(&self) -> &[Value] {
        self.0
            .get("messages")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice)
    }

    /// Whether the client asked for a streamed answer. Absent and null both mean no.
    pub fn stream(&self) -> bool {
        self.0
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    /// Any field of the request, typed or not, exactly as the client sent it.
    pub fn get(&self, field: &str) -> Option<&Value> {
        self.0.get(field)
    }

    /// The request as JSON: the same fields in the same order with the same values.
    pub fn to_vec(&self) -> Vec<u8> {
        // A map of strings to JSON values always serializes.
        serde_json::to_vec(&self.0).unwrap_or_default()
    }
}

/// Fails if any object in the document names the same key twice.
pub fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), serde_json::Error> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    NoDuplicates.deserialize(&mut de)?;
    de.end()
}

struct NoDuplicates;

impl<'de> DeserializeSeed<'de> for NoDuplicates {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NoDuplicates {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(NoDuplicates)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if seen.contains(&key) {
                return Err(A::Error::custom(format!(
                    "the key \"{key}\" appears twice in one object"
                )));
            }
            seen.insert(key);
            map.next_value_seed(NoDuplicates)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_compact_request_comes_back_byte_for_byte() -> TestResult {
        // Field order, an explicit null, a number too large for a float, nested unknown fields: all must survive.
        let json = r#"{"stream":null,"zeta":1,"model":"claude-haiku-5-5","big":123456789012345678901234567890,"precise":0.1000000000000000055511151231257827,"user":"u-1","metadata":{"trace":"t-9"},"messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"t1"}]},{"role":"user","cache_hint":"keep","content":[{"type":"text","text":"look"}]}],"alpha":{"nested":[1,2,{"deep":null}]}}"#;
        let request = ChatRequest::from_slice(json.as_bytes())?;
        assert_eq!(String::from_utf8(request.to_vec())?, json);
        Ok(())
    }

    #[test]
    fn whitespace_and_escapes_change_but_values_do_not() -> TestResult {
        let json = "{ \"model\" : \"m\",\n \"messages\" : [ { \"role\" : \"user\", \"content\" : \"caf\\u00e9\" } ] }";
        let request = ChatRequest::from_slice(json.as_bytes())?;
        let before: Value = serde_json::from_str(json)?;
        let after: Value = serde_json::from_slice(&request.to_vec())?;
        assert_eq!(before, after);
        Ok(())
    }

    #[test]
    fn typed_fields_are_read() -> TestResult {
        let request = ChatRequest::from_slice(br#"{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true,"user":"u-1"}"#)?;
        assert_eq!(request.model(), "m");
        assert!(request.stream());
        assert_eq!(request.messages().len(), 1);
        assert_eq!(request.get("user"), Some(&Value::String("u-1".into())));
        assert_eq!(request.get("absent"), None);
        Ok(())
    }

    #[test]
    fn absent_and_null_stream_both_mean_not_streamed() -> TestResult {
        assert!(!ChatRequest::from_slice(br#"{"model":"m","messages":[]}"#)?.stream());
        assert!(
            !ChatRequest::from_slice(br#"{"model":"m","messages":[],"stream":null}"#)?.stream()
        );
        assert!(
            !ChatRequest::from_slice(br#"{"model":"m","messages":[],"stream":false}"#)?.stream()
        );
        Ok(())
    }

    #[test]
    fn a_duplicate_key_is_refused_at_any_depth() {
        for json in [
            r#"{"model":"m","messages":[],"temperature":0.1,"temperature":0.9}"#,
            r#"{"model":"a","model":"b","messages":[]}"#,
            r#"{"model":"m","messages":[{"role":"user","role":"system"}]}"#,
            r#"{"model":"m","messages":[],"x":{"y":[{"k":1,"k":2}]}}"#,
        ] {
            let err = ChatRequest::from_slice(json.as_bytes());
            assert!(
                err.as_ref()
                    .is_err_and(|e| e.to_string().contains("appears twice")),
                "accepted or wrong error: {json} -> {err:?}"
            );
        }
    }

    #[test]
    fn a_body_that_is_not_a_chat_request_is_refused_with_the_reason() {
        for (json, reason) in [
            ("not json", "not usable JSON"),
            ("[]", "must be a JSON object"),
            (r#"{"messages":[]}"#, "\"model\""),
            (r#"{"model":7,"messages":[]}"#, "\"model\""),
            (r#"{"model":"m"}"#, "\"messages\""),
            (r#"{"model":"m","messages":{}}"#, "\"messages\""),
            (r#"{"model":"m","messages":[{"content":"hi"}]}"#, "\"role\""),
            (
                r#"{"model":"m","messages":[],"stream":"yes"}"#,
                "\"stream\"",
            ),
        ] {
            let err = ChatRequest::from_slice(json.as_bytes());
            assert!(
                err.as_ref().is_err_and(|e| e.to_string().contains(reason)),
                "{json} -> {err:?}"
            );
        }
    }
}
