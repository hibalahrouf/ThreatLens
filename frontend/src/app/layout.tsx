import type { Metadata } from 'next';
import { DM_Sans, Syne } from 'next/font/google';
import './globals.css';
import AppShell from '@/components/AppShell';

const dmSans = DM_Sans({
  subsets: ['latin'],
  variable: '--font-body',
});

const syne = Syne({
  subsets: ['latin'],
  variable: '--font-heading',
});

export const metadata: Metadata = {
  title: 'ThreatLens',
  description: 'See threats. Understand risks. Build secure.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={`${dmSans.variable} ${syne.variable} antialiased flex h-screen overflow-hidden bg-background text-foreground`}>
        <AppShell>
          {children}
        </AppShell>
      </body>
    </html>
  );
}
