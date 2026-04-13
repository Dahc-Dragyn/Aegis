use regex::Regex;

fn main() {
    let msg = "[EventID 1] RuleName:  | UtcTime: 2020-02-10 10:08:24.525 | ProcessGuid: ... | ProcessId: ... | Image: C:\\Users\\Public\\BYOV\\ZAM64\\ppldump.exe | CommandLine: C:\\Users\\Public\\BYOV\\ZAM64\\ppldump.exe -p lsass.exe -o a.png";
    let pattern = r"(?i)CBS_E_MANIFEST_INVALID_ITEM|0x800f080d|\bwhoami\b|netstat\s+-ano|ipconfig\s+/all|\bnmap\b|\bnc\s+-|\bncat\b|\bexploit\b|\bppldump\b|\bmimikatz\b|\bprocdump\b|\bpypykatz\b|lsass\.exe.*dbghelp|ZAM64|BYOV";
    let re = Regex::new(pattern).unwrap();

    if re.is_match(msg) {
        println!("MATCH SUCCESS");
        for cap in re.find_iter(msg) {
            println!("Matched: {}", cap.as_str());
        }
    } else {
        println!("MATCH FAILED");
    }
}
