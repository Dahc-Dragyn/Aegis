import { NextRequest, NextResponse } from 'next/server';
import { getResultsDir, readJsonFile, writeJsonFile } from '@/lib/bridge';
import fs from 'fs';
import path from 'path';

export async function POST(request: NextRequest) {
    const formData = await request.formData();
    const files = formData.getAll('files') as File[];
    const results: any[] = [];
    const resultsDir = getResultsDir();
    
    // Load existing ledger
    let ledger = readJsonFile('telemetry_ledger.json', []);

    for (const file of files) {
        const buffer = Buffer.from(await file.arrayBuffer());
        const filePath = path.join(resultsDir, file.name);
        
        try {
            fs.writeFileSync(filePath, buffer);
            
            // If it's a JSON/JSONL, try to hydrate the ledger
            if (file.name.endsWith(".json") || file.name.endsWith(".jsonl")) {
                const content = buffer.toString('utf-8');
                try {
                    const lines = content.split('\n').filter(l => l.trim());
                    for (const line of lines) {
                        try {
                            const event = JSON.parse(line);
                            if (!event.ingestion_timestamp) {
                                event.ingestion_timestamp = new Date().toISOString();
                            }
                            ledger.unshift(event);
                        } catch (e) {}
                    }
                    results.push({ file: file.name, status: "HYDRATED", path: "A" });
                } catch (e) {
                    results.push({ file: file.name, status: "VAULTED", path: "B" });
                }
            } else {
                results.push({ file: file.name, status: "VAULTED", path: "B" });
            }
        } catch (e) {
            results.push({ file: file.name, status: "FAILED", error: String(e) });
        }
    }

    // Cap ledger
    if (ledger.length > 100000) {
        ledger = ledger.slice(0, 100000);
    }
    writeJsonFile('telemetry_ledger.json', ledger);

    return NextResponse.json({ status: "SUCCESS", ingested: results });
}
