import { NextResponse } from 'next/server';
import { readJsonFile } from '@/lib/bridge';

export async function GET() {
    const status = readJsonFile('isolation_state.json', { isolated: false });
    return NextResponse.json(status);
}
