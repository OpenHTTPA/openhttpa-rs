import type { Metadata } from 'next';
import { Inter, Outfit } from 'next/font/google';
import './globals.css';

const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });
const outfit = Outfit({ subsets: ['latin'], variable: '--font-outfit' });

export const metadata: Metadata = {
  title: 'OpenHTTPA Agent Server Demo',
  description:
    'AI Agent Server Demo showcasing zero-knowledge messaging and AIQL intent translation.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.variable} ${outfit.variable} antialiased min-h-screen bg-slate-950 text-slate-50 font-inter`}
      >
        {children}
      </body>
    </html>
  );
}
