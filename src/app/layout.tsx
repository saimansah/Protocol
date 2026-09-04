import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Protocol by Saiman // Protocol 594',
  description: 'Protocol by Saiman - Top-Secret Ephemeral Communication Network. Copyright and rights claimed by Saiman 2026-2029.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0d0f14] text-[#e2e8f8] antialiased font-mono min-h-screen selection:bg-[#00e5ff]/30 selection:text-[#00e5ff]">
        <div className="bg-grid" />
        <div className="relative z-10">
          {children}
        </div>
      </body>
    </html>
  );
}
