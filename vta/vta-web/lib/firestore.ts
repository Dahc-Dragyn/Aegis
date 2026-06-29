import { getGcpAccessToken } from "./gcp-auth";

export interface AnalysisResult {
  url: string;
  summary: string;
  analysis: string;
  publicScore: number;
  topics: string[];
  keywords: string[];
}

interface FirestoreDocumentRaw {
  fields: {
    url?: { stringValue: string };
    summary?: { stringValue: string };
    analysis?: { stringValue: string };
    public_score?: { integerValue: string };
    topics?: { arrayValue: { values?: { stringValue: string }[] } };
    keywords?: { arrayValue: { values?: { stringValue: string }[] } };
  };
}

interface FirestoreListResponse {
  documents?: FirestoreDocumentRaw[];
}

export function parseFirestoreDocument(doc: FirestoreDocumentRaw): AnalysisResult {
  const fields = doc.fields;
  return {
    url: fields.url?.stringValue || "",
    summary: fields.summary?.stringValue || "",
    analysis: fields.analysis?.stringValue || "",
    publicScore: parseInt(fields.public_score?.integerValue || "0", 10),
    topics: fields.topics?.arrayValue?.values?.map(v => v.stringValue) || [],
    keywords: fields.keywords?.arrayValue?.values?.map(v => v.stringValue) || [],
  };
}

export async function getVtaSignals(): Promise<AnalysisResult[]> {
  const projectId = process.env.GCP_PROJECT_ID;

  if (!projectId) {
    throw new Error("Missing GCP_PROJECT_ID environment variable.");
  }

  const token = await getGcpAccessToken();
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/signals`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    next: { revalidate: 60 },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Firestore REST API returned ${response.status}: ${errorText}`);
  }

  const data = (await response.json()) as FirestoreListResponse;
  if (!data.documents) {
    return [];
  }

  return data.documents.map(parseFirestoreDocument);
}
