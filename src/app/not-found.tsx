import Link from 'next/link';
import { ShieldAlert, ArrowLeft, Terminal, Radio } from 'lucide-react';

export default function NotFound() {
  return (
    <main className="min-h-screen bg-[#05080c] text-slate-200 flex flex-col items-center justify-center p-4 relative overflow-hidden font-mono">
      {/* Background Tactical Grid */}
      <div className="fixed inset-0 pointer-events-none tactical-grid opacity-30 z-0" />

      {/* Decorative Glow */}
      <div className="absolute w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="relative z-10 max-w-md w-full bg-[#0b1017] border border-slate-800 p-8 rounded-2xl shadow-2xl text-center">
        {/* Header Badge */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-950/40 border border-red-500/40 text-red-400 text-[10px] tracking-widest uppercase mb-6 shadow-[0_0_12px_rgba(239,68,68,0.2)]">
          <Radio className="w-3 h-3 text-red-400 animate-pulse" />
          PROTOCOL BY SAIMAN // SECTOR 404
        </div>

        {/* Big Glitch 404 */}
        <div className="text-6xl md:text-7xl font-extrabold text-transparent bg-clip-text bg-gradient-to-b from-white to-slate-600 mb-3 tracking-widest">
          404
        </div>

        {/* Warning Title */}
        <h1 className="text-sm md:text-base font-bold text-cyan-400 uppercase tracking-wider mb-2 flex items-center justify-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400" />
          Classified Sector Not Found
        </h1>

        {/* Subtitle */}
        <p className="text-slate-400 text-xs leading-relaxed mb-8">
          Protocol by Saiman — The requested transmission coordinates do not exist, access has been restricted, or the ephemeral channel has expired.
        </p>

        {/* Return Button */}
        <Link
          href="/"
          className="inline-flex items-center justify-center gap-2 w-full py-2.5 px-4 bg-[#00e5ff] hover:bg-[#33ecff] text-[#05080c] font-bold font-syne text-xs uppercase rounded-xl transition-all shadow-[0_0_16px_rgba(0,229,255,0.25)]"
        >
          <ArrowLeft className="w-4 h-4" />
          Return to Command Hub
        </Link>

        {/* Terminal Info & Footer */}
        <div className="mt-8 pt-4 border-t border-slate-800/80 flex flex-col gap-2 text-[10px] text-slate-500 font-mono">
          <div className="flex items-center justify-between text-slate-600 uppercase tracking-wider">
            <span className="flex items-center gap-1">
              <Terminal className="w-3 h-3" />
              ERR_SECTOR_NULL
            </span>
            <span>ZERO FOOTPRINT</span>
          </div>
          <div className="text-center pt-2 border-t border-slate-800/40">
            Copyright and rights claimed by Saiman 2026-2029
          </div>
        </div>
      </div>
    </main>
  );
}
