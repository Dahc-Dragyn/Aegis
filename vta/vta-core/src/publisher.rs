// Publisher module: Manages end-of-week compilation and Substack publishing

use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use serde_json::Value;
use std::env;
use std::fs;
use std::process::Command;

use crate::brain::{AnalysisResult, Content, GeminiRequest, GeminiResponse, GenerationConfig, Part};
use crate::memory::get_firestore_token;

pub async fn fetch_weekly_signals() -> Result<Vec<AnalysisResult>, Box<dyn std::error::Error + Send + Sync>> {
    let token = get_firestore_token().await?;
    let client = Client::new();
    
    let url = "https://firestore.googleapis.com/v1/projects/vancouver-transparency-agent/databases/(default)/documents/signals";
    
    let res = client
        .get(url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await?;
        return Err(format!("Firestore Fetch Error {}: {}", status, body).into());
    }

    let json_res: Value = res.json().await?;
    
    let seven_days_ago = Utc::now() - Duration::days(7);
    let mut signals = Vec::new();

    if let Some(docs) = json_res.get("documents").and_then(|d| d.as_array()) {
        for doc in docs {
            if let Some(create_time_str) = doc.get("createTime").and_then(|t| t.as_str()) {
                if let Ok(create_time) = create_time_str.parse::<DateTime<Utc>>() {
                    if create_time > seven_days_ago {
                        if let Some(fields) = doc.get("fields") {
                            let summary = fields.get("summary").and_then(|f| f.get("stringValue")).and_then(|s| s.as_str()).unwrap_or("").to_string();
                            let analysis = fields.get("analysis").and_then(|f| f.get("stringValue")).and_then(|s| s.as_str()).unwrap_or("").to_string();
                            
                            let public_score_str = fields.get("public_score").and_then(|f| f.get("integerValue")).and_then(|s| s.as_str()).unwrap_or("0");
                            let public_score: u8 = public_score_str.parse().unwrap_or(0);
                            
                            let mut topics = Vec::new();
                            if let Some(topics_arr) = fields.get("topics").and_then(|f| f.get("arrayValue")).and_then(|a| a.get("values")).and_then(|v| v.as_array()) {
                                for t in topics_arr {
                                    if let Some(s) = t.get("stringValue").and_then(|s| s.as_str()) {
                                        topics.push(s.to_string());
                                    }
                                }
                            }
                            
                            let mut keywords = Vec::new();
                            if let Some(keywords_arr) = fields.get("keywords").and_then(|f| f.get("arrayValue")).and_then(|a| a.get("values")).and_then(|v| v.as_array()) {
                                for k in keywords_arr {
                                    if let Some(s) = k.get("stringValue").and_then(|s| s.as_str()) {
                                        keywords.push(s.to_string());
                                    }
                                }
                            }
                            
                            signals.push(AnalysisResult {
                                summary,
                                topics,
                                keywords,
                                public_score,
                                analysis,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(signals)
}

pub async fn format_html_digest(signals: &[AnalysisResult]) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let api_key = env::var("GEMINI_API_KEY").map_err(|_| "GEMINI_API_KEY must be set in the environment")?;
    
    let serialized_signals = serde_json::to_string_pretty(signals)?;
    
    let prompt = format!(
        "You are an expert newsletter editor for the Vancouver Transparency Agent.\n\
        Format the following civic signals into a professional HTML 'Insider Brief' suitable for a Substack newsletter.\n\
        Only output the raw HTML, no markdown code blocks or wrapper tags around the HTML.\n\n\
        Signals:\n{}",
        serialized_signals
    );

    let payload = GeminiRequest {
        contents: vec![Content {
            parts: vec![Part {
                text: prompt,
            }],
        }],
        generation_config: GenerationConfig {
            response_mime_type: "text/plain".to_string(),
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
    
    let raw_html = gemini_res
        .candidates
        .first()
        .and_then(|c| c.content.parts.first())
        .map(|p| &p.text)
        .ok_or("Failed to extract text from Gemini response")?
        .clone();
        
    let clean_html = raw_html.trim().strip_prefix("```html").unwrap_or(&raw_html)
                             .strip_prefix("```").unwrap_or(&raw_html)
                             .strip_suffix("```").unwrap_or(&raw_html)
                             .trim().to_string();

    Ok(clean_html)
}

pub async fn generate_weekly_digest() {
    println!("Executing Friday Substack digest generation...");
    
    match fetch_weekly_signals().await {
        Ok(signals) => {
            if signals.is_empty() {
                println!("No signals found for the past week. Skipping digest.");
                return;
            }
            
            match format_html_digest(&signals).await {
                Ok(html_digest) => {
                    let output_path = "workspace/digest_output.html";
                    let _ = fs::create_dir_all("workspace");
                    
                    if let Err(e) = fs::write(output_path, &html_digest) {
                        eprintln!("Failed to write HTML digest to {}: {}", output_path, e);
                        return;
                    }
                    
                    println!("Digest written to {}. Spawning python publisher...", output_path);
                    
                    match Command::new("python")
                        .arg("vta_publisher.py")
                        .arg(output_path)
                        .status() 
                    {
                        Ok(status) => {
                            if status.success() {
                                println!("Successfully published Substack digest.");
                            } else {
                                eprintln!("Python publisher failed with status: {}", status);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to spawn Python publisher process: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to compile HTML digest: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to fetch weekly signals: {}", e);
        }
    }
}
