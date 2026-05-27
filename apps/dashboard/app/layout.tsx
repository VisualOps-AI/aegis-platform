import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis Dashboard",
  description: "AI Agent Security Dashboard — Attack Surface, Compliance, and Threat Analysis",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen relative">
        <div
          className="pointer-events-none fixed inset-0 z-0"
          style={{
            background: 'radial-gradient(ellipse 60% 40% at 50% 0%, rgba(124,92,255,0.06), transparent)',
          }}
        />
        <nav
          className="sticky top-0 z-50 border-b backdrop-blur-md"
          style={{
            borderColor: 'var(--border)',
            background: 'rgba(18, 18, 26, 0.85)',
          }}
        >
          <div className="mx-auto max-w-7xl px-6 h-12 flex items-center justify-between">
            <a href="/" className="flex items-center gap-2.5 no-underline group">
              <div
                className="w-2 h-2 rounded-full"
                style={{
                  background: 'var(--accent)',
                  boxShadow: '0 0 8px var(--accent)',
                }}
              />
              <span
                className="text-sm font-bold tracking-widest"
                style={{ color: 'var(--accent)' }}
              >
                AEGIS
              </span>
              <span
                className="text-[10px] tracking-wider uppercase"
                style={{ color: 'var(--text-muted)' }}
              >
                Security
              </span>
            </a>
            <div className="flex items-center gap-1">
              <NavLink href="/" label="Dashboard" />
              <NavLink href="/scans" label="Scans" />
            </div>
          </div>
        </nav>
        <main className="relative z-10 mx-auto max-w-7xl px-6 py-6">
          {children}
        </main>
      </body>
    </html>
  );
}

function NavLink({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      className="no-underline px-3 py-1.5 text-xs tracking-wide uppercase transition-colors"
      style={{ color: 'var(--text-dim)', borderRadius: 'var(--radius)' }}
      onMouseOver={undefined}
    >
      {label}
    </a>
  );
}
