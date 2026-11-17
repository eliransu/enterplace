//! Embeddings requests in OpenAI's format (`POST /v1/embeddings`) as each provider takes them, and their answers
//! back in OpenAI's format, usage included, so a client and the gateway's metering read one shape.
//!
//! Formats as documented on 2026-11-14:
//! - Amazon Titan Text Embeddings: <https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-titan-embed-text.html>
//! - Cohere Embed on Bedrock: <https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-embed.html>
//! - Gemini API: <https://ai.google.dev/api/embeddings>
//! - Vertex AI: <https://docs.cloud.google.com/vertex-ai/generative-ai/docs/model-reference/text-embeddings-api>
//! - Cohere v2: <https://docs.cohere.com/reference/embed>
//! - watsonx.ai: <https://cloud.ibm.com/apidocs/watsonx-ai#text-embeddings>

use serde_json::{Map, Value, json};

use crate::translate::{Result, describe, fail, object, untranslatable};

/// The provider API an embeddings request is translated to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Amazon Titan Text Embeddings on Bedrock InvokeModel: one text per call.
    Titan,
    /// Cohere Embed on Bedrock InvokeModel.
    BedrockCohere,
    /// The Gemini API's batchEmbedContents.
    Gemini,
    /// Vertex AI's predict for text embedding models.
    Vertex,
    /// Cohere's v2 embed.
    Cohere,
    /// watsonx.ai text/embeddings.
    Watsonx,
}

impl Target {
    fn name(self) -> &'static str {
        match self {
            Target::Titan => "Amazon Titan embeddings on Bedrock",
            Target::BedrockCohere => "Cohere embeddings on Bedrock",
            Target::Gemini => "the Gemini API's embeddings",
            Target::Vertex => "Vertex AI's embeddings",
            Target::Cohere => "Cohere's embed API",
            Target::Watsonx => "watsonx.ai's embeddings",
        }
    }

    /// The target for a Bedrock model ID, or None for a model Bedrock does not embed with.
    pub fn bedrock(model_id: &str) -> Option<Target> {
        match crate::converse::family(model_id) {
            "amazon" if model_id.contains("titan-embed") => Some(Target::Titan),
            "cohere" if model_id.contains("embed") => Some(Target::BedrockCohere),
            _ => None,
        }
    }
}

/// The texts of an OpenAI embeddings request, and the other fields it set.
fn texts(request: &Value, target: Target) -> Result<(Vec<String>, Map<String, Value>)> {
    let fields = object(request, "The request body")?;
    let texts = match &request["input"] {
        Value::String(text) => vec![text.clone()],
        Value::Array(items) if !items.is_empty() && items.iter().all(Value::is_string) => items
            .iter()
            .filter_map(|t| t.as_str().map(String::from))
            .collect(),
        Value::Array(items) if items.is_empty() => {
            return fail("\"input\" is an empty list. Send at least one text.".into());
        }
        _ => {
            return fail(format!(
                "\"input\" must be a string or a list of strings for {}: token IDs cannot be sent there. Send the text.",
                target.name()
            ));
        }
    };
    let mut rest = Map::new();
    for (key, value) in fields {
        match key.as_str() {
            "model" | "input" => {}
            _ if value.is_null() => {}
            // An end-user ID for OpenAI's abuse monitoring: no answer depends on it.
            "user" => {}
            "encoding_format" if value == "float" => {}
            "dimensions" if value.is_u64() => {
                rest.insert(key.clone(), value.clone());
            }
            // Cohere and Vertex AI embed a query and a document differently; the caller may say which.
            "input_type"
                if value.is_string()
                    && matches!(
                        target,
                        Target::BedrockCohere | Target::Cohere | Target::Vertex | Target::Gemini
                    ) =>
            {
                rest.insert(key.clone(), value.clone());
            }
            _ => return untranslatable(&describe(key, value), target.name()),
        }
    }
    Ok((texts, rest))
}

/// Cohere's input types, and Google's task types for the same purposes.
fn task_type(input_type: Option<&str>) -> Result<Option<&'static str>> {
    Ok(match input_type {
        None => None,
        Some("search_document") => Some("RETRIEVAL_DOCUMENT"),
        Some("search_query") => Some("RETRIEVAL_QUERY"),
        Some("classification") => Some("CLASSIFICATION"),
        Some("clustering") => Some("CLUSTERING"),
        Some(other) => {
            return fail(format!(
                "\"input_type\" \"{other}\" is not one Enterplace maps: send search_document, search_query, classification or clustering."
            ));
        }
    })
}

/// An OpenAI embeddings request as the body `target` takes. `model` is the provider's name for the model, which
/// Gemini, Cohere and watsonx want in the body; `project` is the watsonx project.
pub fn request(target: Target, model: &str, body: &Value, project: Option<&str>) -> Result<Value> {
    let (texts, rest) = texts(body, target)?;
    let input_type = rest.get("input_type").and_then(Value::as_str);
    let dimensions = rest.get("dimensions").cloned();
    Ok(match target {
        Target::Titan => {
            let [text] = texts.as_slice() else {
                return fail(format!(
                    "\"input\" holds {} texts, and Amazon Titan embeds one per request. Send one text per request.",
                    texts.len()
                ));
            };
            let mut out = json!({"inputText": text});
            if let Some(d) = dimensions {
                out["dimensions"] = d;
            }
            out
        }
        Target::BedrockCohere | Target::Cohere => {
            let mut out = json!({
                "texts": texts,
                "input_type": input_type.unwrap_or("search_document"),
                "embedding_types": ["float"],
            });
            if target == Target::Cohere {
                out["model"] = json!(model);
            }
            if let Some(d) = dimensions {
                out["output_dimension"] = d;
            }
            out
        }
        Target::Gemini => {
            let task = task_type(input_type)?;
            let requests: Vec<Value> = texts
                .iter()
                .map(|text| {
                    let mut one = json!({"model": format!("models/{model}"), "content": {"parts": [{"text": text}]}});
                    if let Some(task) = task {
                        one["taskType"] = json!(task);
                    }
                    if let Some(d) = &dimensions {
                        one["outputDimensionality"] = d.clone();
                    }
                    one
                })
                .collect();
            json!({"requests": requests})
        }
        Target::Vertex => {
            let task = task_type(input_type)?;
            let instances: Vec<Value> = texts
                .iter()
                .map(|text| {
                    let mut one = json!({"content": text});
                    if let Some(task) = task {
                        one["task_type"] = json!(task);
                    }
                    one
                })
                .collect();
            let mut out = json!({"instances": instances});
            if let Some(d) = dimensions {
                out["parameters"] = json!({"outputDimensionality": d});
            }
            out
        }
        Target::Watsonx => {
            if dimensions.is_some() {
                return untranslatable("The parameter \"dimensions\"", target.name());
            }
            json!({"inputs": texts, "model_id": model, "project_id": project.unwrap_or_default()})
        }
    })
}

/// An upper bound on the tokens of texts, for an answer that reports none: a token is at least one byte.
pub fn bytes_of(body: &Value) -> u64 {
    match &body["input"] {
        Value::String(t) => t.len() as u64,
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|t| t.len() as u64)
            .sum(),
        _ => 0,
    }
}

/// The provider's embeddings answer in OpenAI's format. `model` is the name the caller sent. `tokens` is the count
/// the provider gave outside the body (Bedrock's `X-Amzn-Bedrock-Input-Token-Count` header), or for the Gemini API,
/// whose answer counts nothing, the upper bound of [`bytes_of`].
pub fn answer(target: Target, model: &str, answer: &Value, tokens: Option<u64>) -> Result<Value> {
    let floats = |v: &Value| -> Result<Value> {
        match v {
            Value::Array(items) if items.iter().all(Value::is_number) => Ok(v.clone()),
            _ => fail(
                "The provider's answer holds an embedding that is not a list of numbers.".into(),
            ),
        }
    };
    let (vectors, counted): (Vec<Value>, Option<u64>) = match target {
        Target::Titan => (
            vec![floats(&answer["embedding"])?],
            answer["inputTextTokenCount"].as_u64(),
        ),
        Target::BedrockCohere | Target::Cohere => {
            let list = answer["embeddings"]
                .get("float")
                .unwrap_or(&answer["embeddings"]);
            let Some(list) = list.as_array() else {
                return fail("The provider's answer holds no embeddings.".into());
            };
            let vectors = list.iter().map(floats).collect::<Result<Vec<_>>>()?;
            (
                vectors,
                answer["meta"]["billed_units"]["input_tokens"].as_u64(),
            )
        }
        Target::Gemini => {
            let list = answer["embeddings"]
                .as_array()
                .map_or(&[][..], Vec::as_slice);
            (
                list.iter()
                    .map(|e| floats(&e["values"]))
                    .collect::<Result<Vec<_>>>()?,
                None,
            )
        }
        Target::Vertex => {
            let list = answer["predictions"]
                .as_array()
                .map_or(&[][..], Vec::as_slice);
            let counted = list
                .iter()
                .map(|p| {
                    p["embeddings"]["statistics"]["token_count"]
                        .as_f64()
                        .unwrap_or_default() as u64
                })
                .sum();
            (
                list.iter()
                    .map(|p| floats(&p["embeddings"]["values"]))
                    .collect::<Result<Vec<_>>>()?,
                Some(counted),
            )
        }
        Target::Watsonx => {
            let list = answer["results"].as_array().map_or(&[][..], Vec::as_slice);
            (
                list.iter()
                    .map(|r| floats(&r["embedding"]))
                    .collect::<Result<Vec<_>>>()?,
                answer["input_token_count"].as_u64(),
            )
        }
    };
    if vectors.is_empty() {
        return fail("The provider's answer holds no embeddings.".into());
    }
    let prompt = counted.or(tokens).unwrap_or_default();
    let data: Vec<Value> = vectors
        .into_iter()
        .enumerate()
        .map(|(index, embedding)| json!({"object": "embedding", "index": index, "embedding": embedding}))
        .collect();
    Ok(json!({
        "object": "list",
        "data": data,
        "model": model,
        "usage": {"prompt_tokens": prompt, "total_tokens": prompt},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn requests_take_each_providers_shape() -> TestResult {
        let one = json!({"model": "e", "input": "hello", "dimensions": 256});
        let many = json!({"model": "e", "input": ["a", "b"], "input_type": "search_query"});
        assert_eq!(
            request(Target::Titan, "e", &one, None)?,
            json!({"inputText": "hello", "dimensions": 256})
        );
        let two = json!({"model": "e", "input": ["a", "b"]});
        assert!(
            request(Target::Titan, "e", &two, None)
                .is_err_and(|e| e.to_string().contains("one text per request"))
        );
        let cohere = request(Target::BedrockCohere, "e", &many, None)?;
        assert_eq!(cohere["input_type"], "search_query");
        assert!(cohere.get("model").is_none());
        let gemini = request(Target::Gemini, "gemini-embedding-001", &many, None)?;
        assert_eq!(
            gemini["requests"][1]["model"],
            "models/gemini-embedding-001"
        );
        assert_eq!(gemini["requests"][0]["taskType"], "RETRIEVAL_QUERY");
        let vertex = request(Target::Vertex, "text-embedding-005", &one, None)?;
        assert_eq!(vertex["parameters"]["outputDimensionality"], 256);
        let watsonx = request(Target::Watsonx, "ibm/slate", &two, Some("p1"))?;
        assert_eq!(watsonx["project_id"], "p1");
        let base64 = json!({"model": "e", "input": "x", "encoding_format": "base64"});
        assert!(
            request(Target::Vertex, "e", &base64, None)
                .is_err_and(|e| e.to_string().contains("encoding_format"))
        );
        Ok(())
    }

    #[test]
    fn answers_come_back_as_openai_embeddings_with_usage() -> TestResult {
        let titan = answer(
            Target::Titan,
            "e",
            &json!({"embedding": [0.1, 0.2], "inputTextTokenCount": 3}),
            None,
        )?;
        assert_eq!(titan["data"][0]["embedding"], json!([0.1, 0.2]));
        assert_eq!(titan["usage"]["prompt_tokens"], 3);
        let cohere = answer(
            Target::BedrockCohere,
            "e",
            &json!({"embeddings": [[1.0], [2.0]]}),
            Some(9),
        )?;
        assert_eq!(cohere["data"][1]["index"], 1);
        assert_eq!(cohere["usage"]["prompt_tokens"], 9);
        let vertex = answer(
            Target::Vertex,
            "e",
            &json!({"predictions": [
                {"embeddings": {"values": [0.5], "statistics": {"token_count": 4.0}}},
                {"embeddings": {"values": [0.6], "statistics": {"token_count": 2.0}}}
            ]}),
            None,
        )?;
        assert_eq!(vertex["usage"]["total_tokens"], 6);
        let v2 = answer(
            Target::Cohere,
            "e",
            &json!({"embeddings": {"float": [[0.3]]}, "meta": {"billed_units": {"input_tokens": 5}}}),
            None,
        )?;
        assert_eq!(v2["usage"]["prompt_tokens"], 5);
        Ok(())
    }
}
