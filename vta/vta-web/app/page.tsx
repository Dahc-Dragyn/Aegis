import { getVtaSignals, AnalysisResult } from "@/lib/firestore";

export const runtime = "edge";

// Fallback mock data in case environment variables aren't injected yet during initial deploy
const MOCK_SIGNALS: AnalysisResult[] = [
  {
    url: "https://civicclerk.vancouver.ca/meeting/1024",
    summary: "Public hearing on high-density residential development near Transit Hubs.",
    analysis: "This signal represents high public interest as it alters municipal zoning laws for all areas within 800m of SkyTrain stations, enabling multi-family development up to 20 stories.",
    publicScore: 9,
    topics: ["Zoning & Planning", "Transit Housing"],
    keywords: ["SkyTrain", "Zoning Amendment", "Density", "Affordability"]
  },
  {
    url: "https://civicclerk.vancouver.ca/meeting/1025",
    summary: "Routine approval of parks maintenance budget adjustments.",
    analysis: "Low-impact administrative adjustment. Reallocates $45k from playground maintenance to tree pruning schedules. No policy changes or major public opposition expected.",
    publicScore: 3,
    topics: ["Parks & Recreation", "Budgeting"],
    keywords: ["Budget", "Tree Pruning", "Operations"]
  }
];

export default async function Home() {
  let signals: AnalysisResult[] = [];
  let error: string | null = null;

  try {
    signals = await getVtaSignals();
  } catch (e: any) {
    console.error("Failed to load signals, displaying fallback mock data:", e.message);
    signals = MOCK_SIGNALS;
    error = `Displaying demo data. Setup environment variables to load from live database: ${e.message}`;
  }

  return (
    <div className="min-h-screen bg-[#fcfbf9] text-slate-900 flex flex-col font-serif selection:bg-red-800/10 selection:text-red-900">
      {/* Newspaper Container */}
      <div className="max-w-4xl mx-auto w-full px-6 md:px-8 py-10 flex-grow">
        
        {/* Newspaper Masthead */}
        <header className="text-center mb-8 border-b-4 border-double border-slate-900 pb-4">
          <p className="text-[10px] font-sans uppercase tracking-widest text-slate-600 mb-1 font-semibold">
            Vancouver Municipal Transparency Digest
          </p>
          <h1 className="text-4xl md:text-5xl font-black font-serif tracking-tight text-slate-900 uppercase italic">
            Vancouver Transparency Weekly
          </h1>
          
          {/* Issue Details Bar */}
          <div className="flex justify-between items-center border-y border-slate-950/80 py-2 mt-4 text-[11px] font-sans uppercase tracking-wider text-slate-700 font-medium">
            <div>Vol. I • No. I</div>
            <div className="hidden sm:block text-center font-bold">"Civic Transparency in the Digital Age"</div>
            <div>{new Date().toLocaleDateString('en-US', { month: 'long', year: 'numeric', day: 'numeric' })}</div>
            <div>Free / Edge</div>
          </div>
        </header>

        {/* Warning/Info Box in news layout */}
        {error && (
          <div className="mb-8 p-4 border border-red-800/30 bg-red-50/50 text-red-950 text-xs font-sans italic">
            [EDITOR'S NOTE]: {error}
          </div>
        )}

        {/* Main Editorial Layout (Two Columns) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          
          {/* Left/Main Column: Articles Feed (2/3 width) */}
          <main className="md:col-span-2 space-y-10">
            {signals.length === 0 ? (
              <p className="text-slate-500 italic text-center py-10">No new dispatches filed at this hour.</p>
            ) : (
              signals.map((signal, idx) => {
                const isHigh = signal.publicScore >= 7;
                const isMedium = signal.publicScore >= 5 && signal.publicScore < 7;
                const impactText = isHigh ? "Impact: High" : isMedium ? "Impact: Medium" : "Impact: Low";
                const impactColor = isHigh ? "text-red-800 font-bold" : isMedium ? "text-amber-800 font-semibold" : "text-slate-600 font-medium";

                return (
                  <article key={idx} className="group border-b border-slate-350 pb-10 last:border-b-0 last:pb-0">
                    {/* Category / Score Line */}
                    <div className="flex items-center justify-between text-[11px] font-sans uppercase tracking-widest text-slate-500 mb-2">
                      <span>Dispatch #{idx + 1}</span>
                      <span className="font-semibold">Relevance Score: {signal.publicScore}/10</span>
                    </div>

                    {/* Headline */}
                    <h2 className="text-xl md:text-2xl font-bold text-slate-950 font-serif leading-tight mb-3 group-hover:underline decoration-red-800 decoration-1 underline-offset-4">
                      {signal.summary}
                    </h2>

                    {/* Meta tag topics */}
                    <div className="flex flex-wrap gap-1.5 mb-4">
                      {signal.topics.map((topic, i) => (
                        <span key={i} className="text-[10px] font-sans font-semibold tracking-wider uppercase bg-slate-100 text-slate-700 px-2 py-0.5 rounded">
                          {topic}
                        </span>
                      ))}
                    </div>

                    {/* Signal Analysis (styled as a blockquote) */}
                    <div className="border-l-4 border-slate-900 pl-4 py-2 my-4 bg-slate-50 italic text-slate-800 leading-relaxed text-sm">
                      <h4 className="text-[10px] font-sans font-bold uppercase tracking-wider text-slate-500 not-italic mb-1">
                        Signal Analysis:
                      </h4>
                      "{signal.analysis}"
                    </div>

                    {/* Footer / Citations line */}
                    <div className="flex flex-wrap items-center justify-between gap-4 mt-6 pt-2 text-xs font-sans">
                      <span className={`${impactColor} uppercase tracking-wider text-[11px]`}>
                        {impactText}
                      </span>
                      <a
                        href={signal.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-slate-600 hover:text-red-800 underline decoration-slate-400 hover:decoration-red-800 transition-colors"
                      >
                        Source Document [{idx + 1}] ↗
                      </a>
                    </div>
                  </article>
                );
              })
            )}
          </main>

          {/* Right Column: Sidebar (1/3 width) */}
          <aside className="border-t md:border-t-0 md:border-l border-slate-350 pt-8 md:pt-0 md:pl-6 space-y-8 font-sans">
            
            {/* System Status Block */}
            <div className="border border-slate-900 p-4 bg-slate-50">
              <h3 className="font-serif font-bold text-slate-950 uppercase tracking-wide border-b border-slate-900 pb-2 mb-3 text-sm">
                System Status
              </h3>
              <ul className="space-y-2 text-xs text-slate-700">
                <li className="flex justify-between">
                  <span>Edge Nodes:</span>
                  <span className="font-semibold text-emerald-800">NOMINAL</span>
                </li>
                <li className="flex justify-between">
                  <span>Deployment:</span>
                  <span>Cloudflare Pages</span>
                </li>
                <li className="flex justify-between">
                  <span>Routing:</span>
                  <span>vta.aiyoda.app</span>
                </li>
                <li className="flex justify-between">
                  <span>Total Scouted:</span>
                  <span className="font-semibold">{signals.length}</span>
                </li>
              </ul>
            </div>

            {/* Editorial Note */}
            <div className="space-y-3">
              <h3 className="font-serif font-bold text-slate-950 uppercase tracking-wide border-b border-slate-900 pb-2 text-sm">
                Editorial Note
              </h3>
              <p className="text-xs leading-relaxed text-slate-600 italic">
                The Vancouver Transparency Agent daemon is a background scraper monitoring city council agendas, civic reports, and regulatory filings. Using advanced LLM classification, the system extracts high-value policy shifts and publishes updates daily.
              </p>
            </div>

            {/* Keyword Index */}
            <div>
              <h3 className="font-serif font-bold text-slate-950 uppercase tracking-wide border-b border-slate-900 pb-2 mb-3 text-sm">
                Keyword Index
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {Array.from(new Set(signals.flatMap(s => s.keywords))).map((kw, i) => (
                  <span key={i} className="text-[10px] bg-slate-100 hover:bg-slate-200 text-slate-800 px-2 py-0.5 rounded cursor-default">
                    #{kw}
                  </span>
                ))}
              </div>
            </div>

          </aside>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-50 py-6 text-center text-xs font-sans text-slate-500 tracking-wider">
        <p className="uppercase font-semibold">Vancouver Transparency Weekly • ISSN 2816-4352</p>
        <p className="mt-1">Edge-Rendered via Cloudflare Pages. Built on Next.js 15.</p>
      </footer>
    </div>
  );
}
