interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

let cachedToken: { token: string; expiresAt: number } | null = null;

function pemToDer(pem: string): ArrayBuffer {
  // Replace escaped \n with actual newlines, and remove header/footer/whitespace
  const cleanPem = pem
    .replace(/\\n/g, "\n")
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  
  const binary = atob(cleanPem);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer.buffer;
}

function base64Url(strOrArray: string | ArrayBuffer): string {
  let binary = "";
  if (typeof strOrArray === "string") {
    binary = btoa(unescape(encodeURIComponent(strOrArray)));
  } else {
    const bytes = new Uint8Array(strOrArray);
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    binary = btoa(binary);
  }
  return binary.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function generateJwt(clientEmail: string, privateKeyPem: string): Promise<string> {
  const header = {
    alg: "RS256",
    typ: "JWT",
  };

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const encodedHeader = base64Url(JSON.stringify(header));
  const encodedPayload = base64Url(JSON.stringify(payload));
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  const der = pemToDer(privateKeyPem);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    der,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const encoder = new TextEncoder();
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    encoder.encode(unsignedToken)
  );

  const encodedSignature = base64Url(signature);
  return `${unsignedToken}.${encodedSignature}`;
}

export async function getGcpAccessToken(): Promise<string> {
  const clientEmail = process.env.GCP_CLIENT_EMAIL;
  const privateKey = process.env.GCP_PRIVATE_KEY;

  if (!clientEmail || !privateKey) {
    throw new Error("Missing GCP credentials in environment variables (GCP_CLIENT_EMAIL or GCP_PRIVATE_KEY).");
  }

  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.expiresAt > now + 60) {
    return cachedToken.token;
  }

  const jwt = await generateJwt(clientEmail, privateKey);
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Google OAuth token exchange failed: ${errText}`);
  }

  const data = (await response.json()) as TokenResponse;
  cachedToken = {
    token: data.access_token,
    expiresAt: now + data.expires_in - 100, // expire slightly early
  };

  return data.access_token;
}
