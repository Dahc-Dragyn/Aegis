import fs from 'fs';
import path from 'path';

// The Aegis Core results directory
const RESULTS_DIR = 'C:\\Antigravity projects\\Rust\\aegis\\forensic_results';

export function getResultsDir() {
    if (!fs.existsSync(RESULTS_DIR)) {
        fs.mkdirSync(RESULTS_DIR, { recursive: true });
    }
    return RESULTS_DIR;
}

export function readJsonFile(filename: string, defaultValue: any = {}) {
    const filePath = path.join(getResultsDir(), filename);
    if (!fs.existsSync(filePath)) return defaultValue;
    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        return JSON.parse(content);
    } catch (e) {
        console.error(`[BRIDGE] FAILED_TO_READ_${filename}:`, e);
        return defaultValue;
    }
}

export function readTextFile(filename: string, defaultValue: string = "") {
    const filePath = path.join(getResultsDir(), filename);
    if (!fs.existsSync(filePath)) return defaultValue;
    try {
        return fs.readFileSync(filePath, 'utf-8');
    } catch (e) {
        console.error(`[BRIDGE] FAILED_TO_READ_${filename}:`, e);
        return defaultValue;
    }
}

export function writeJsonFile(filename: string, data: any) {
    const filePath = path.join(getResultsDir(), filename);
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
        return true;
    } catch (e) {
        console.error(`[BRIDGE] FAILED_TO_WRITE_${filename}:`, e);
        return false;
    }
}
