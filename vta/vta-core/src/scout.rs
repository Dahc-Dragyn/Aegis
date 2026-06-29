// Scout module: Handles web collection protocol

use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct ExtractionRequest {
    pub url: String,
    pub formats: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "waitFor", skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<u32>,
}

impl ExtractionRequest {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            formats: vec!["markdown".to_string()],
            timeout: None,
            wait_for: None,
        }
    }
}

#[derive(Deserialize)]
pub struct FirecrawlData {
    pub markdown: Option<String>,
}

#[derive(Deserialize)]
pub struct ExtractionResponse {
    pub data: Option<FirecrawlData>,
    pub markdown: Option<String>,
}

impl ExtractionResponse {
    pub fn get_markdown(&self) -> String {
        if let Some(md) = &self.markdown {
            return md.clone();
        }
        if let Some(data) = &self.data {
            if let Some(md) = &data.markdown {
                return md.clone();
            }
        }
        String::new()
    }
}

pub async fn extract_meeting_data(url: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let firecrawl_endpoint = std::env::var("FIRECRAWL_API_URL").unwrap_or_else(|_| "http://127.0.0.1:3002/v1/scrape".to_string());
    println!("Dispatching direct REST extraction request for target URL: {} via Firecrawl API: {}", url, firecrawl_endpoint);

    let client = Client::new();
    let mut payload = ExtractionRequest::new(url);
    payload.timeout = Some(30000);
    payload.wait_for = Some(5000);

    let res = client
        .post(&firecrawl_endpoint)
        .json(&payload)
        .send()
        .await?;

    let extraction: ExtractionResponse = res.json().await?;
    let markdown = extraction.get_markdown();

    Ok(markdown)
}

pub fn is_valid_signal(markdown: &str) -> bool {
    if markdown.len() < 200 {
        return false;
    }

    let lower_md = markdown.to_lowercase();
    if lower_md.contains("no published meeting files") || lower_md.contains("access denied") {
        return false;
    }

    true
}

pub async fn run_vta_pipeline() {
    println!("Executing 6-hour VTA extraction pipeline...");
    let target_url = "https://vancouverwa.portal.civicclerk.com/";

    match extract_meeting_data(target_url).await {
        Ok(markdown) => {
            let valid = is_valid_signal(&markdown);
            println!("Extraction successful. Valid signal: {}", valid);
            
            if valid {
                match crate::brain::analyze_meeting_text(&markdown).await {
                    Ok(analysis) => {
                        if analysis.public_score >= 7 {
                            match crate::memory::save_analyzed_signal(&analysis, target_url).await {
                                Ok(_) => {
                                    println!("Pipeline execution complete. High-value signal persisted to Firestore.");
                                }
                                Err(e) => {
                                    eprintln!("Failed to persist high-value signal to Firestore: {}", e);
                                }
                            }
                        } else {
                            println!("Signal dropped: Public score {} does not meet the persistence threshold.", analysis.public_score);
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to analyze meeting text via Gemini API: {}", e);
                        return;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to extract meeting data: {}", e);
        }
    }
}
