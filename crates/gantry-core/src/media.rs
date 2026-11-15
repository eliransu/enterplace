//! Image generation and rerank requests in OpenAI's and Cohere's shapes, as the providers that have their own take
//! them: Imagen and Gemini image models on the Gemini API and Vertex AI, and Amazon Titan Image Generator, Nova
//! Canvas, Stability AI and the rerank models on Amazon Bedrock's InvokeModel. Each answer comes back in the caller's
//! shape. A parameter with no equivalent is an error naming it, never dropped.
//!
//! Bodies follow the providers' public API references: Google's Imagen `predict` and `generateContent`, and the
//! model parameter pages of the Amazon Bedrock user guide.

use serde_json::{Value, json};

/// Which image API a model speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageTarget {
    /// Imagen: `:predict` with `instances` and `parameters`.
    Imagen,
    /// A Gemini model that writes images: `:generateContent` with image output.
    GeminiImage,
    /// Amazon Titan Image Generator and Nova Canvas: `taskType: TEXT_IMAGE`.
    Amazon,
    /// Stability AI's Stable Image and Stable Diffusion 3 models.
    Stability,
    /// Stability AI's SDXL 1.0, which has its own older body.
    StabilityXl,
}

impl ImageTarget {
    /// The API of a model on the Gemini API or Vertex AI, by its name.
    pub fn google(model: &str) -> Self {
        if model.starts_with("imagen") || model.contains("/imagen") {
            ImageTarget::Imagen
        } else {
            ImageTarget::GeminiImage
        }
    }

    /// The API of a Bedrock model ID, when it is an image model Gantry translates to. An inference profile's
    /// region prefix (`us.amazon.nova-canvas-v1:0`) does not matter.
    pub fn bedrock(id: &str) -> Option<Self> {
        if id.contains("amazon.titan-image-generator") || id.contains("amazon.nova-canvas") {
            Some(ImageTarget::Amazon)
        } else if id.contains("stability.stable-diffusion-xl") {
            Some(ImageTarget::StabilityXl)
        } else if id.contains("stability.") {
            Some(ImageTarget::Stability)
        } else {
            None
        }
    }
}

/// `size` as width and height.
fn size_of(request: &Value) -> Result<Option<(u64, u64)>, String> {
    let Some(size) = request.get("size").filter(|s| !s.is_null()) else {
        return Ok(None);
    };
    size.as_str()
        .and_then(|s| s.split_once('x'))
        .and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?)))
        .filter(|(w, h)| *w > 0 && *h > 0)
        .map(Some)
        .ok_or_else(|| {
            "\"size\" must be <width>x<height> in pixels, for example \"1024x1024\".".to_string()
        })
}

/// A size as one of the aspect ratios a model takes.
fn ratio(size: (u64, u64), allowed: &[&str], whose: &str) -> Result<String, String> {
    fn gcd(a: u64, b: u64) -> u64 {
        if b == 0 { a } else { gcd(b, a % b) }
    }
    let by = gcd(size.0, size.1);
    let exact = format!("{}:{}", size.0 / by, size.1 / by);
    if allowed.contains(&exact.as_str()) {
        return Ok(exact);
    }
    // OpenAI's own sizes are close to, not exactly, the ratios these models name.
    let near = match (size.0, size.1) {
        (1792, 1024) | (1536, 1024) => "16:9",
        (1024, 1792) | (1024, 1536) => "9:16",
        _ => "",
    };
    if allowed.contains(&near) {
        return Ok(near.to_string());
    }
    Err(format!(
        "\"size\" {}x{} is not an aspect ratio {whose} takes ({}). Send a size of one of those shapes, for example \"1024x1024\".",
        size.0,
        size.1,
        allowed.join(", ")
    ))
}

/// An OpenAI image generation request as `target`'s own body.
pub fn image_request(target: ImageTarget, request: &Value) -> Result<Value, String> {
    let whose = match target {
        ImageTarget::Imagen => "Imagen",
        ImageTarget::GeminiImage => "Gemini's image output",
        ImageTarget::Amazon => "Amazon's image models on Bedrock",
        ImageTarget::Stability | ImageTarget::StabilityXl => "Stability AI's models on Bedrock",
    };
    let Some(fields) = request.as_object() else {
        return Err("the body must be a JSON object with a \"prompt\".".into());
    };
    for key in fields.keys() {
        let known = matches!(
            key.as_str(),
            "model" | "prompt" | "n" | "size" | "response_format"
        ) || (key == "quality" && target == ImageTarget::Amazon);
        if !known {
            return Err(format!(
                "The parameter \"{key}\" has no equivalent in {whose}. Remove it."
            ));
        }
    }
    let prompt = request["prompt"]
        .as_str()
        .filter(|p| !p.is_empty())
        .ok_or("\"prompt\" must be the text to draw.")?;
    match request.get("response_format").and_then(Value::as_str) {
        None | Some("b64_json") => {}
        Some(other) => {
            return Err(format!(
                "response_format \"{other}\" has no equivalent in {whose}, which answers with the image itself. Send \"b64_json\", or leave it out."
            ));
        }
    }
    let n = match request.get("n").filter(|n| !n.is_null()) {
        None => 1,
        Some(n) => n
            .as_u64()
            .filter(|n| (1..=8).contains(n))
            .ok_or("\"n\" must be a number of images from 1 to 8.")?,
    };
    let size = size_of(request)?;
    let one_only = |what: &str| {
        if n == 1 {
            Ok(())
        } else {
            Err(format!(
                "{what} draws one image per request, and \"n\" is {n}. Send n: 1, once per image."
            ))
        }
    };
    Ok(match target {
        ImageTarget::Imagen => {
            let mut parameters = json!({"sampleCount": n});
            if let Some(size) = size {
                parameters["aspectRatio"] =
                    ratio(size, &["1:1", "3:4", "4:3", "9:16", "16:9"], whose)?.into();
            }
            json!({"instances": [{"prompt": prompt}], "parameters": parameters})
        }
        ImageTarget::GeminiImage => {
            one_only("A Gemini image model")?;
            let mut config = json!({"responseModalities": ["TEXT", "IMAGE"]});
            if let Some(size) = size {
                config["imageConfig"] = json!({"aspectRatio": ratio(
                    size,
                    &["1:1", "2:3", "3:2", "3:4", "4:3", "4:5", "5:4", "9:16", "16:9", "21:9"],
                    whose,
                )?});
            }
            json!({
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": config,
            })
        }
        ImageTarget::Amazon => {
            let mut config = json!({"numberOfImages": n});
            if let Some((width, height)) = size {
                config["width"] = width.into();
                config["height"] = height.into();
            }
            match request.get("quality").and_then(Value::as_str) {
                None => {}
                Some("standard") => config["quality"] = "standard".into(),
                Some("hd" | "high" | "premium") => config["quality"] = "premium".into(),
                Some(other) => {
                    return Err(format!(
                        "quality \"{other}\" has no equivalent in {whose}. Send standard or hd."
                    ));
                }
            }
            json!({
                "taskType": "TEXT_IMAGE",
                "textToImageParams": {"text": prompt},
                "imageGenerationConfig": config,
            })
        }
        ImageTarget::Stability => {
            one_only("This Stability AI model")?;
            let mut out = json!({"prompt": prompt, "output_format": "png"});
            if let Some(size) = size {
                out["aspect_ratio"] = ratio(
                    size,
                    &[
                        "16:9", "1:1", "21:9", "2:3", "3:2", "4:5", "5:4", "9:16", "9:21",
                    ],
                    whose,
                )?
                .into();
            }
            out
        }
        ImageTarget::StabilityXl => {
            let mut out = json!({"text_prompts": [{"text": prompt}], "samples": n});
            if let Some((width, height)) = size {
                out["width"] = width.into();
                out["height"] = height.into();
            }
            out
        }
    })
}

/// `target`'s answer as OpenAI's: `data`, each image as `b64_json`. An answer with no image (the provider's own
/// filter withheld it) is an error that says why, when the provider did.
pub fn image_answer(target: ImageTarget, answer: &Value, created: u64) -> Result<Value, String> {
    let list = |v: &Value| v.as_array().cloned().unwrap_or_default();
    let images: Vec<Value> = match target {
        ImageTarget::Imagen => list(&answer["predictions"])
            .iter()
            .filter_map(|p| p.get("bytesBase64Encoded").cloned())
            .collect(),
        ImageTarget::GeminiImage => list(&answer["candidates"])
            .iter()
            .flat_map(|c| list(&c["content"]["parts"]))
            .filter_map(|p| {
                p.get("inlineData")
                    .or_else(|| p.get("inline_data"))
                    .and_then(|d| d.get("data"))
                    .cloned()
            })
            .collect(),
        ImageTarget::Amazon | ImageTarget::Stability => list(&answer["images"]),
        ImageTarget::StabilityXl => list(&answer["artifacts"])
            .iter()
            .filter_map(|a| a.get("base64").cloned())
            .collect(),
    };
    let images: Vec<Value> = images.into_iter().filter(|i| i.is_string()).collect();
    if images.is_empty() {
        let why = [
            &answer["predictions"][0]["raiFilteredReason"],
            &answer["promptFeedback"]["blockReason"],
            &answer["candidates"][0]["finishReason"],
            &answer["error"],
            &answer["finish_reasons"][0],
        ]
        .into_iter()
        .find_map(Value::as_str)
        .unwrap_or("it gave no reason");
        return Err(format!("the provider's answer holds no image: {why}"));
    }
    let mut out = json!({
        "created": created,
        "data": images.into_iter().map(|i| json!({"b64_json": i})).collect::<Vec<_>>(),
    });
    // A Gemini image model bills by the token and says how many.
    let used = &answer["usageMetadata"];
    if let (Some(input), Some(output)) = (
        used["promptTokenCount"].as_u64(),
        used["candidatesTokenCount"].as_u64(),
    ) {
        out["usage"] =
            json!({"input_tokens": input, "output_tokens": output, "total_tokens": input + output});
    }
    Ok(out)
}

/// A Cohere-shaped rerank request as the body Bedrock's InvokeModel takes for its rerank models (Cohere Rerank,
/// Amazon Rerank).
pub fn bedrock_rerank_request(id: &str, request: &Value) -> Result<Value, String> {
    for key in request.as_object().map(|o| o.keys()).into_iter().flatten() {
        if !matches!(key.as_str(), "model" | "query" | "documents" | "top_n") {
            return Err(format!(
                "The parameter \"{key}\" has no equivalent in Bedrock's rerank models. Remove it."
            ));
        }
    }
    let query = request["query"]
        .as_str()
        .ok_or("\"query\" must be the text to rank the documents against.")?;
    let documents = request["documents"]
        .as_array()
        .filter(|d| !d.is_empty() && d.iter().all(Value::is_string))
        .ok_or("\"documents\" must be a list of strings for Bedrock's rerank models.")?;
    let mut out = json!({"query": query, "documents": documents});
    if let Some(n) = request.get("top_n").filter(|n| !n.is_null()) {
        out["top_n"] = n
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("\"top_n\" must be a number of results, 1 or more.")?
            .into();
    }
    // Cohere's models on Bedrock want the version of their API named.
    if id.contains("cohere.") {
        out["api_version"] = 2.into();
    }
    Ok(out)
}

/// Bedrock's rerank answer as Cohere's: each result's index and relevance score.
pub fn rerank_answer(model: &str, answer: &Value) -> Value {
    let results: Vec<Value> = answer["results"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| json!({"index": r["index"], "relevance_score": r["relevance_score"]}))
        .collect();
    json!({"object": "list", "model": model, "results": results})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_image_api_takes_its_own_body_and_a_field_with_no_equivalent_is_named()
    -> Result<(), String> {
        let ask = json!({"model": "m", "prompt": "a red kite", "n": 2, "size": "1792x1024"});
        assert_eq!(
            image_request(ImageTarget::Imagen, &ask)?,
            json!({"instances": [{"prompt": "a red kite"}], "parameters": {"sampleCount": 2, "aspectRatio": "16:9"}})
        );
        assert_eq!(
            image_request(ImageTarget::Amazon, &ask)?["imageGenerationConfig"],
            json!({"numberOfImages": 2, "width": 1792, "height": 1024})
        );
        let one = json!({"prompt": "a red kite", "size": "1024x1024"});
        assert_eq!(
            image_request(ImageTarget::Stability, &one)?,
            json!({"prompt": "a red kite", "output_format": "png", "aspect_ratio": "1:1"})
        );
        assert_eq!(
            image_request(ImageTarget::GeminiImage, &one)?["generationConfig"]["imageConfig"],
            json!({"aspectRatio": "1:1"})
        );
        for (target, bad, names) in [
            (ImageTarget::Stability, ask.clone(), "one image per request"),
            (
                ImageTarget::Imagen,
                json!({"prompt": "x", "style": "vivid"}),
                "\"style\"",
            ),
            (
                ImageTarget::Imagen,
                json!({"prompt": "x", "response_format": "url"}),
                "response_format",
            ),
            (
                ImageTarget::Imagen,
                json!({"prompt": "x", "size": "1000x333"}),
                "aspect ratio",
            ),
            (ImageTarget::Amazon, json!({"n": 1}), "prompt"),
        ] {
            let Err(why) = image_request(target, &bad) else {
                return Err(format!("{bad} was translated"));
            };
            assert!(why.contains(names), "{why}");
        }
        assert_eq!(
            ImageTarget::bedrock("us.amazon.nova-canvas-v1:0"),
            Some(ImageTarget::Amazon)
        );
        assert_eq!(
            ImageTarget::bedrock("stability.sd3-5-large-v1:0"),
            Some(ImageTarget::Stability)
        );
        assert_eq!(ImageTarget::bedrock("anthropic.claude-3"), None);
        Ok(())
    }

    #[test]
    fn each_image_answer_comes_back_as_openais_and_a_withheld_image_says_why() -> Result<(), String>
    {
        let imagen =
            json!({"predictions": [{"bytesBase64Encoded": "QQ==", "mimeType": "image/png"}]});
        assert_eq!(
            image_answer(ImageTarget::Imagen, &imagen, 7)?,
            json!({"created": 7, "data": [{"b64_json": "QQ=="}]})
        );
        let gemini = json!({"candidates": [{"content": {"parts": [{"text": "here"}, {"inlineData": {"mimeType": "image/png", "data": "Qg=="}}]}}], "usageMetadata": {"promptTokenCount": 5, "candidatesTokenCount": 1290}});
        let out = image_answer(ImageTarget::GeminiImage, &gemini, 7)?;
        assert_eq!(out["data"], json!([{"b64_json": "Qg=="}]));
        assert_eq!(out["usage"]["output_tokens"], 1290);
        assert_eq!(
            image_answer(
                ImageTarget::StabilityXl,
                &json!({"artifacts": [{"base64": "Qw=="}]}),
                7
            )?["data"][0]["b64_json"],
            "Qw=="
        );
        let Err(why) = image_answer(
            ImageTarget::Imagen,
            &json!({"predictions": [{"raiFilteredReason": "the prompt names a person"}]}),
            7,
        ) else {
            return Err("an answer with no image was passed on".into());
        };
        assert!(why.contains("names a person"), "{why}");
        Ok(())
    }

    #[test]
    fn a_rerank_request_becomes_bedrocks_and_its_answer_coheres() -> Result<(), String> {
        let ask = json!({"model": "rerank", "query": "q", "documents": ["a", "b"], "top_n": 1});
        assert_eq!(
            bedrock_rerank_request("cohere.rerank-v3-5:0", &ask)?,
            json!({"query": "q", "documents": ["a", "b"], "top_n": 1, "api_version": 2})
        );
        assert!(
            bedrock_rerank_request("amazon.rerank-v1:0", &ask)?
                .get("api_version")
                .is_none()
        );
        assert!(
            bedrock_rerank_request(
                "amazon.rerank-v1:0",
                &json!({"query": "q", "documents": ["a"], "rank_fields": ["t"]})
            )
            .is_err()
        );
        assert_eq!(
            rerank_answer(
                "rerank",
                &json!({"results": [{"index": 1, "relevance_score": 0.9}]})
            ),
            json!({"object": "list", "model": "rerank", "results": [{"index": 1, "relevance_score": 0.9}]})
        );
        Ok(())
    }
}
