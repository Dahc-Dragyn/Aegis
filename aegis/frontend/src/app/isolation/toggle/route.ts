import { NextResponse } from 'next/server';
import { readJsonFile, writeJsonFile } from '@/lib/bridge';

export async function POST() {
    const status = readJsonFile('isolation_state.json', { isolated: false });
    const newState = { isolated: !status.isolated };
    writeJsonFile('isolation_state.json', newState);
    return NextResponse.json(newState);
}
