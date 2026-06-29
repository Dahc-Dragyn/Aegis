// Brain module: Coordinates contextual interpretation via Gemini API

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Serialize, Deserialize, Debug)]
pub struct AnalysisResult {
    pub summary: String,
    pub topics: Vec<String>,
    pub keywords: Vec<String>,
    pub public_score: u8,
    pub analysis: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Part {
    pub text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Content {
    pub parts: Vec<Part>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationConfig {
    pub response_mime_type: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiRequest {
    pub contents: Vec<Content>,
    pub generation_config: GenerationConfig,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiResponsePart {
    pub text: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiResponseContent {
    pub parts: Vec<GeminiResponsePart>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiResponseCandidate {
    pub content: GeminiResponseContent,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiResponse {
    pub candidates: Vec<GeminiResponseCandidate>,
}

pub async fn analyze_meeting_text(markdown: &str) -> Result<AnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
    let api_key = env::var("GEMINI_API_KEY").map_err(|_| "GEMINI_API_KEY must be set in the environment")?;
    
    let prompt = format!(
        "You are an expert 'City Hall Reporter'. Analyze the following municipal meeting markdown.\n\
        Identify the civic impact, and score the public relevance on a scale from 1 to 10.\n\
        Return your response strictly as JSON adhering to this exact schema:\n\
        {{\n\
            \"summary\": \"string\",\n\
            \"topics\": [\"string\"],\n\
            \"keywords\": [\"string\"],\n\
            \"public_score\": number,\n\
            \"analysis\": \"string\"\n\
        }}\n\n\
        Markdown to analyze:\n{}",
        markdown
    );

    let payload = GeminiRequest {
        contents: vec![Content {
            parts: vec![Part {
                text: prompt,
            }],
        }],
        generation_config: GenerationConfig {
            response_mime_type: "application/json".to_string(),
        },
    };

    let client = Client::new();
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key={}",
        api_key
    );

    let res = client
        .post(&url)
        .json(&payload)
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await?;
        return Err(format!("Gemini API Error {}: {}", status, body).into());
    }

    let gemini_res: GeminiResponse = res.json().await?;
    
    let raw_text = gemini_res
        .candidates
        .first()
        .and_then(|c| c.content.parts.first())
        .map(|p| &p.text)
        .ok_or("Failed to extract text from Gemini response")?;

    let analysis: AnalysisResult = serde_json::from_str(raw_text)?;

    Ok(analysis)
}
