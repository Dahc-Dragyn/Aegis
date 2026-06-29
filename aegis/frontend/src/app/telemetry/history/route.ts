import { NextResponse } from 'next/server';
import { readJsonFile } from '@/lib/bridge';

export async function GET() {
    const history = readJsonFile('telemetry_ledger.json', []);
    return NextResponse.json(history);
}
