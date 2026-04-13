use regex::Regex;

fn main() {
    let messages = vec![
        "User failed to login",
        "Audit log was cleared",
        "Started process: nc -lvp 4444",
        "Execution of /tmp/exploit.sh",
        "Modified /etc/shadow",
        "An attempt was made to reset an account's password",
    ];

    let patterns = vec![
        ("AU-2", r"(?i)(failed password for|authentication failure|invalid user)"),
        ("AU-9", r"(?i)(log cleared|audit log was cleared|event 1102|event 104|systemctl stop (rsyslog|auditd)|net stop (eventlog|sysmon)|kill -9.*(rsyslog|auditd|eventlog))"),
        ("CM-5", r"(?i)(/etc/systemd/system/|reg\s+add.*\\Run|crontab\s+-e|schtasks\s+/create)"),
        ("SC-7", r"(?i)(curl.*\|\s*sh|wget|certutil\s+-urlcache|base64\s+-d|powershell\s+-enc|execution of /tmp/)"),
        ("SI-4", r"(?i)(whoami|id|netstat\s+-ano|ipconfig\s+/all|nmap|nc\s+-|ncat|exploit)"),
        ("AC-6", r"(?i)(sudo:|su:|root login|/etc/shadow|/etc/passwd|/etc/sudoers|SAM\s+hive)"),
        ("IA-2", r"(?i)(password changed|passwd:|reset an account's password|chfn:|usermod:)"),
    ];

    for msg in messages {
        let mut matched = false;
        for (id, pat) in &patterns {
            let re = Regex::new(pat).unwrap();
            if re.is_match(msg) {
                println!("MATCH: '{}' -> {}", msg, id);
                matched = true;
                break;
            }
        }
        if !matched {
            println!("MISS: '{}'", msg);
        }
    }
}
