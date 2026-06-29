import { NextResponse } from 'next/server';
import { getResultsDir } from '@/lib/bridge';
import fs from 'fs';

export async function GET() {
    const resultsDir = getResultsDir();
    let resultsSize = 0;
    try {
        const stats = fs.statSync(resultsDir);
        resultsSize = stats.size;
    } catch (e) {}

    return NextResponse.json({
        offline_mode: false,
        results_dir: resultsDir,
        timestamp: new Date().toISOString(),
        storage_usage: `${(resultsSize / 1048576).toFixed(2)} MB`,
        status: "OPERATIONAL"
    });
}
