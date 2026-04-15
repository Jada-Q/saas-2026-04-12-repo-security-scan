import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Analytics } from "@vercel/analytics/next";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "GHScan — Is Your GitHub Repo Leaking Secrets?",
  description: "Free security scanner: 152+ secret patterns, dependency vulnerabilities, source map leaks, and homoglyph detection. Runs in your browser.",
  metadataBase: new URL("https://ghscan.vercel.app"),
  openGraph: {
    title: "GHScan — Is Your GitHub Repo Leaking Secrets?",
    description: "Free security scanner: 152+ secret patterns, dependency vulnerabilities, source map leaks, and homoglyph detection.",
    url: "https://ghscan.vercel.app",
    siteName: "GHScan",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "GHScan — Is Your GitHub Repo Leaking Secrets?",
    description: "Free security scanner with 152+ secret patterns. Runs in your browser, nothing leaves your machine.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased dark`}
      suppressHydrationWarning
    >
      <body className="min-h-full flex flex-col">{children}<Analytics /></body>
    </html>
  );
}
