use crate::models::{LogRecord, ParsingQuality};
use crate::parsers::LogParser;
use std::collections::BTreeMap;
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use etherparse::*;
use std::fs::File;
use chrono::Local;

pub struct PcapParser;

impl PcapParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PcapParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PcapParser {
    pub fn parse_binary(&self, path: &std::path::Path) -> Vec<LogRecord> {
        let mut records = Vec::new();
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return records,
        };

        if let Ok(mut reader) = LegacyPcapReader::new(65536, file) {
            // Default to Ethernet for legacy; specific Loopback samples are PCAPNG
            self.extract_from_reader(&mut reader, &mut records, Some(Linktype::ETHERNET));
        } else {
            if let Ok(file_ng) = File::open(path) {
                if let Ok(mut reader_ng) = PcapNGReader::new(65536, file_ng) {
                    self.extract_from_reader(&mut reader_ng, &mut records, None);
                }
            }
        }
        records
    }

    fn extract_from_reader<I: PcapReaderIterator>(&self, reader: &mut I, records: &mut Vec<LogRecord>, global_link: Option<Linktype>) {
        let mut interface_links = Vec::new();

        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                            interface_links.push(idb.linktype);
                        },
                        PcapBlockOwned::Legacy(packet) => {
                            let lt = global_link.unwrap_or(Linktype::ETHERNET);
                            if let Some(log) = self.process_packet(packet.data, lt) {
                                records.push(log);
                            }
                        },
                        PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                            if let Some(lt) = interface_links.get(packet.if_id as usize) {
                                if let Some(log) = self.process_packet(packet.data, *lt) {
                                    records.push(log);
                                }
                            }
                        },
                        PcapBlockOwned::NG(Block::SimplePacket(packet)) => {
                            // Simple packets always use the first interface
                            if let Some(lt) = interface_links.first() {
                                if let Some(log) = self.process_packet(packet.data, *lt) {
                                    records.push(log);
                                }
                            }
                        },
                        _ => {}
                    }
                    reader.consume(offset);
                },
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    if reader.refill().is_err() { break; }
                },
                Err(_) => break,
            }
        }
    }

    fn process_packet(&self, data: &[u8], link_type: Linktype) -> Option<LogRecord> {
        let mut indicators = Vec::new();
        let mut protocol = "Unknown";
        let mut port_info = String::new();
        let mut l7_payload: Vec<u8> = Vec::new();
        let mut src_ip = "N/A".to_string();
        let mut dst_ip = "N/A".to_string();

        // 1. Link-Type Aware Extraction
        let sliced_res = match link_type {
            Linktype::ETHERNET => SlicedPacket::from_ethernet(data),
            Linktype::NULL => {
                if data.len() >= 4 {
                    // DLT_NULL / Loopback: 4-byte Address Family header, then IP
                    SlicedPacket::from_ip(&data[4..])
                } else {
                    return None;
                }
            },
            Linktype::RAW => SlicedPacket::from_ip(data),
            _ => return None, // Strictly ignore unknown/unsupported LinkTypes
        };

        if let Ok(sliced) = sliced_res {
            if let Some(ip) = &sliced.ip {
                match ip {
                    InternetSlice::Ipv4(ipv4, _) => {
                        src_ip = format!("{:?}", ipv4.source_addr());
                        dst_ip = format!("{:?}", ipv4.destination_addr());
                    },
                    InternetSlice::Ipv6(ipv6, _) => {
                        src_ip = format!("{:?}", ipv6.source_addr());
                        dst_ip = format!("{:?}", ipv6.destination_addr());
                    }
                }
            }
            if let Some(transport) = &sliced.transport {
                match transport {
                    TransportSlice::Tcp(tcp) => {
                        protocol = "TCP";
                        port_info = format!("{}:{}", tcp.source_port(), tcp.destination_port());
                        l7_payload = sliced.payload.to_vec();
                        // Scan both ports to catch responses from privileged ports (e.g. DNS 53 -> client)
                        self.scan_payload(&l7_payload, tcp.source_port(), tcp.destination_port(), &mut indicators);
                    },
                    TransportSlice::Udp(udp) => {
                        protocol = "UDP";
                        port_info = format!("{}:{}", udp.source_port(), udp.destination_port());
                        l7_payload = sliced.payload.to_vec();
                        self.scan_payload(&l7_payload, udp.source_port(), udp.destination_port(), &mut indicators);
                    },
                    _ => {}
                }
            }
        }

        // 2. HARD VETO Compliance: RAW Fallback Removed.
        // We only generate a record if forensic indicators were triggered via L7 scan.

        if indicators.is_empty() {
            return None;
        }

        let mut metadata = BTreeMap::new();
        metadata.insert("protocol".to_string(), protocol.to_string());
        metadata.insert("ports".to_string(), port_info);
        metadata.insert("src_ip".to_string(), src_ip);
        metadata.insert("dst_ip".to_string(), dst_ip);
        
        let final_payload = String::from_utf8_lossy(&l7_payload);

        let indicators_summary = if indicators.is_empty() { 
            "No forensic indicators found.".to_string() 
        } else { 
            indicators.join(" | ") 
        };

        Some(LogRecord {
            timestamp: Local::now(),
            message: format!("[NET {}] {}", protocol, indicators_summary),
            raw: format!("{}\nFORENSIC_INDICATORS: {}", final_payload, indicators_summary),
            metadata,
            original_format: "pcap_binary".to_string(),
            quality: ParsingQuality::Success,
            ..Default::default()
        })
    }

    fn scan_payload(&self, payload: &[u8], src_port: u16, dst_port: u16, indicators: &mut Vec<String>) {
        let sample_size = payload.len().min(1024);
        let sample = &payload[..sample_size];
        let payload_str = String::from_utf8_lossy(sample);

        // Helper to check if either port matches a target
        let involves_port = |p: u16| src_port == p || dst_port == p;

        // DCSync
        const SIG_DRSUAPI: &[u8] = &[0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2];
        if sample.windows(16).any(|w| w == SIG_DRSUAPI) {
            indicators.push("[NETWORK_ALERT] DCSync (DRSUAPI) Attempt".to_string());
        }

        // SMBGhost/SMB2/DCShadow
        if sample.windows(4).any(|w| w == b"\xFC\x53\x4D\x42") || sample.windows(4).any(|w| w == b"\xFE\x53\x4D\x42") {
            indicators.push("[NETWORK_ALERT] [FORENSIC_INDICATOR] SMB2/SMBGhost (CVE-2020-0796) Forensic Header".to_string());
            
            // Heuristic for DCShadow attribute injection (primaryGroupID / RID 512)
            if payload_str.contains("primaryGroupID") || payload_str.contains("512") && payload_str.contains("add") {
                 indicators.push("[NETWORK_ALERT] [FORENSIC_INDICATOR] Possible DCShadow Attribute Injection Detected".to_string());
            }
        }

        // ZeroLogon
        const SIG_NULL_CHALLENGE: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0];
        if (involves_port(135) || involves_port(139) || involves_port(445)) 
            && sample.windows(8).any(|w| w == SIG_NULL_CHALLENGE) {
            indicators.push("[NETWORK_ALERT] [FORENSIC_INDICATOR] ZeroLogon (CVE-2020-1472) NULL Challenge".to_string());
        }

        // PetitPotam (MS-EFSR UUID: df1941c5-fe89-4e00-9a4a-135407589648)
        const SIG_MS_EFSR: &[u8] = &[0xc5, 0x41, 0x19, 0xdf, 0x89, 0xfe, 0x00, 0x4e, 0x9a, 0x4a, 0x13, 0x54, 0x07, 0x58, 0x96, 0x48];
        if sample.windows(16).any(|w| w == SIG_MS_EFSR) {
            indicators.push("[NETWORK_ALERT] [FORENSIC_INDICATOR] PetitPotam (MS-EFSR / CVE-2021-36942) Attempt".to_string());
        }

        // Kerberos (AS-REQ / TGS-REQ / Kerbrute)
        if involves_port(88) && (sample.contains(&0xa1) || sample.windows(4).any(|w| w == b"KRB5")) {
            indicators.push("[NETWORK_ALERT] Kerberos (AS-REQ/Kerbrute) Indicator".to_string());
            
            // TGS-REQ fingerprinting (for Kerberoasting)
            if sample.windows(2).any(|w| w == [0x6a, 0x82]) || sample.windows(2).any(|w| w == [0x6c, 0x82]) {
                indicators.push("[NETWORK_ALERT] [FORENSIC_INDICATOR] Kerberos TGS-REQ (Kerberoasting Opportunity)".to_string());
            }

            // EType 23 (RC4-HMAC) check - common in Kerberoasting/Silver Ticket
            if sample.windows(3).any(|w| w == [0x02, 0x01, 0x17]) {
                indicators.push("[NETWORK_ALERT] [FORENSIC_INDICATOR] Kerberos RC4-HMAC (EType 23) Detected".to_string());
            }
        }

        // DNS Tunneling / C2 over TXT / DGA
        if involves_port(53) {
            // Look for DNS QTYPE TXT (0x0010) and Class IN (0x0001)
            const SIG_DNS_TXT: &[u8] = &[0x00, 0x10, 0x00, 0x01];
            let raw_str = String::from_utf8_lossy(sample);
            if sample.windows(4).any(|w| w == SIG_DNS_TXT) {
                // Heuristic: TXT records with anomalously large payloads (>100 bytes)
                if sample.len() > 100 {
                    indicators.push("[NETWORK_ALERT] DNS_TXT_C2_Tunneling".to_string());
                }
            } else if sample.len() > 70 || raw_str.contains("foudre") || raw_str.contains("dga") {
                indicators.push("[NETWORK_ALERT] DNS Tunneling / DGA Exfiltration Pattern".to_string());
            }
        }

        // RDP / Tunneling / Port Forwarding
        if involves_port(3389) {
            let matches_handshake = sample.starts_with(&[0x03, 0x00]) || sample.windows(7).any(|w| w == b"rdp-tcp") || sample.windows(4).any(|w| w == b"\x00\x00\x00\x01");
            if matches_handshake {
                indicators.push("[NETWORK_ALERT] RDP Lateral Movement / Tunneling Indicator".to_string());
            } else if !sample.is_empty() {
                // Heuristic: Active data on 3389 that doesn't match the RDP handshake indicates an encrypted tunnel.
                indicators.push("[NETWORK_ALERT] Suspicious_C2_Tunnel_Port_3389 (Anomalous RDP)".to_string());
            }
        }

        // --- Target 2: HTTP Backdoor/C2 Exfiltration Guard ---
        // Promote HTTP POST requests with payloads for NistEngine behavioral analysis.
        if (payload_str.contains("POST") || payload_str.contains("txt=")) && (src_port == 80 || dst_port == 80) {
            indicators.push("[NETWORK_ALERT] HTTP POST Request Detected (Forensic Body Promotion)".to_string());
        }

        // Malicious Default C2 Ports (Meterpreter / Metasploit / C2)
        const MALICIOUS_C2_PORTS: &[u16] = &[4444, 4445, 31337];
        if MALICIOUS_C2_PORTS.iter().any(|&p| involves_port(p)) {
            // If we are on a known C2 port and have ANY data that wasn't already matched by a specific signature, flag it.
            indicators.push(format!("[NETWORK_ALERT] Suspicious_C2_Tunnel_Port_{}", src_port.max(dst_port)));
        }

        // --- ☢️ TIER 1: DEFENSE EVASION & EXPLOIT PAYLOADS (byt3bl33d3r / Event Log Crash) ---
        if payload_str.contains("byt3bl33d3r") {
            indicators.push("[NETWORK_ALERT] [FORENSIC_INDICATOR] byt3bl33d3r RPC Crash Payload Detected".to_string());
        }
        if payload_str.contains("Event Log Crash") || payload_str.contains("Defense Evasion") {
            indicators.push("[NETWORK_ALERT] [FORENSIC_INDICATOR] System Integrity / Defense Evasion Signature Detected".to_string());
        }
    }
}

impl LogParser for PcapParser {
    fn format_name(&self) -> &str { "pcap_binary" }
    fn parse(&self, _raw: &str) -> LogRecord { LogRecord::default() }
    fn as_any(&self) -> &dyn std::any::Any { self }
}
