use aegis::parsers::evtx::EvtxParser;
use aegis::parsers::LogParser;
use evtx::EvtxParser as RawParser;
use aegis::NistEngine;
use aegis::config::AppConfig;
use std::path::Path;
use std::sync::Arc;

fn main() {
    let path = Path::new("logs/latmov_impersoate.evtx");
    let parser = EvtxParser::new();
    let config = AppConfig::default_config();
    let engine = NistEngine::new(config.clone()).unwrap();
    let mut raw_parser = RawParser::from_path(path).unwrap();

    let mut count = 0;
    for record in raw_parser.records_json() {
        match record {
            Ok(rec) => {
                let log_record = parser.parse(&rec.data);
                let analyzed = engine.analyze_batch(&[Arc::new(log_record)], &config);
                let result = &analyzed[0];
                
                if let Some(id) = result.metadata.get("nist_control_id") {
                    println!("--- RECORD INSPECTION ---");
                    println!("Metadata ID: {}", id);
                    println!("Matches Result: {:?}", engine.matches(result).map(|m| &m.0.control_id));
                    
                    if id != "AU-3" && id != "AU-2" {
                        println!("Finding Type: {}", id);
                        println!("Message: {}", result.message);
                        count += 1;
                    }
                    println!("------------------------");
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }
    println!("Total findings in latmov: {}", count);
}
