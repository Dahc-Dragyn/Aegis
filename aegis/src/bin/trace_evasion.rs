use aegis::parsers::evtx::EvtxParser;
use aegis::parsers::LogParser;
use evtx::EvtxParser as RawParser;
use std::path::Path;

fn main() {
    let path = Path::new("logs/evasion.evtx");
    let parser = EvtxParser::new();
    let mut raw_parser = RawParser::from_path(path).unwrap();

    let mut count = 0;
    for record in raw_parser.records_json() {
        match record {
            Ok(rec) => {
                let log_record = parser.parse(&rec.data);
                let msg = log_record.message.to_lowercase();
                
                // Search for the specific indicators the user mentioned
                if msg.contains("ppldump") || msg.contains("zam64") || msg.contains("byov") || msg.contains("lsass") {
                    println!("--- FINDING DETECTED IN RAW ---");
                    println!("Timestamp: {}", log_record.timestamp);
                    println!("Source: {:?}", log_record.source);
                    println!("Message: {}", log_record.message);
                    println!("Metadata: {:?}", log_record.metadata);
                    println!("-------------------------------");
                    count += 1;
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }
    println!("Total suspicious events seen by test script: {}", count);
}
