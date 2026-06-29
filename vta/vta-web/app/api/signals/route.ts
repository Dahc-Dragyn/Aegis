import { NextResponse } from "next/server";
import { getVtaSignals } from "@/lib/firestore";

export const runtime = "edge";

export async function GET() {
  try {
    const signals = await getVtaSignals();
    return NextResponse.json({ signals });
  } catch (error: any) {
    console.error("Firestore Edge Route Error:", error);
    return NextResponse.json(
      { error: error.message || "Failed to fetch signals" },
      { status: 500 }
    );
  }
}
