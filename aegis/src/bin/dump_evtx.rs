use evtx::EvtxParser;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dump_evtx <path_to_evtx>");
        return;
    }
    let path = Path::new(&args[1]);
    let mut parser = EvtxParser::from_path(path).unwrap();

    for record in parser.records_json() {
        match record {
            Ok(rec) => {
                println!("{}", rec.data);
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}
