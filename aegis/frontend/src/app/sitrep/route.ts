import { NextResponse } from 'next/server';
import { readTextFile } from '@/lib/bridge';

export async function GET() {
    const content = readTextFile('COMMANDERS_BRIEF.md', "WAITING FOR SIGNAL...");
    let sitrep = content;
    
    // Support the split format if present
    if (content.includes("---")) {
        const parts = content.split("---");
        if (parts.length >= 3) {
            sitrep = parts[1].trim();
        }
    }
    
    return NextResponse.json({ sitrep });
}
