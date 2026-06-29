// Memory module: Handles database interaction with Firestore

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::brain::AnalysisResult;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StringValue {
    pub string_value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IntegerValue {
    pub integer_value: String, // Firestore REST returns integers as strings
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArrayValueInner {
    pub values: Option<Vec<StringValue>>, 
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArrayValue {
    pub array_value: ArrayValueInner,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum FirestoreValue {
    String(StringValue),
    Integer(IntegerValue),
    Array(ArrayValue),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Document {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub fields: HashMap<String, FirestoreValue>,
}

#[derive(Deserialize, Debug)]
pub struct ListDocumentsResponse {
    pub documents: Option<Vec<Document>>,
}

pub fn result_to_fields(signal: &AnalysisResult, url: &str) -> HashMap<String, FirestoreValue> {
    let mut fields = HashMap::new();
    
    fields.insert(
        "url".to_string(), 
        FirestoreValue::String(StringValue { string_value: url.to_string() })
    );
    fields.insert(
        "summary".to_string(), 
        FirestoreValue::String(StringValue { string_value: signal.summary.clone() })
    );
    fields.insert(
        "analysis".to_string(), 
        FirestoreValue::String(StringValue { string_value: signal.analysis.clone() })
    );
    fields.insert(
        "public_score".to_string(), 
        FirestoreValue::Integer(IntegerValue { integer_value: signal.public_score.to_string() })
    );
    
    let topics_values = signal.topics.iter().map(|t| StringValue { string_value: t.clone() }).collect();
    fields.insert(
        "topics".to_string(),
        FirestoreValue::Array(ArrayValue { array_value: ArrayValueInner { values: Some(topics_values) } })
    );
    
    let keywords_values = signal.keywords.iter().map(|k| StringValue { string_value: k.clone() }).collect();
    fields.insert(
        "keywords".to_string(),
        FirestoreValue::Array(ArrayValue { array_value: ArrayValueInner { values: Some(keywords_values) } })
    );
    
    fields
}

pub async fn get_firestore_token() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let provider = gcp_auth::provider().await?;
    let scopes = &["https://www.googleapis.com/auth/datastore"];
    let token = provider.token(scopes).await?;
    Ok(token.as_str().to_string())
}

pub async fn fetch_processed_bookmarks() -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let token = get_firestore_token().await?;
    let client = Client::new();
    
    let url = "https://firestore.googleapis.com/v1/projects/vancouver-transparency-agent/databases/(default)/documents/bookmarks";
    
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

    let list_res: ListDocumentsResponse = res.json().await?;
    
    let mut bookmarks = Vec::new();
    if let Some(docs) = list_res.documents {
        for doc in docs {
            if let Some(FirestoreValue::String(s)) = doc.fields.get("url") {
                bookmarks.push(s.string_value.clone());
            }
        }
    }
    
    Ok(bookmarks)
}

pub async fn save_analyzed_signal(signal: &AnalysisResult, url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let token = get_firestore_token().await?;
    let client = Client::new();
    
    let endpoint = "https://firestore.googleapis.com/v1/projects/vancouver-transparency-agent/databases/(default)/documents/signals";
    
    let document = Document {
        name: None,
        fields: result_to_fields(signal, url),
    };
    
    let res = client
        .post(endpoint)
        .header("Authorization", format!("Bearer {}", token))
        .json(&document)
        .send()
        .await?;
        
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await?;
        return Err(format!("Firestore Save Error {}: {}", status, body).into());
    }
    
    Ok(())
}
