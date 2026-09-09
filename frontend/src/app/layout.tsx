import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

const ibmPlexSans = IBM_Plex_Sans({
  variable: "--font-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

const ibmPlexMono = IBM_Plex_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "InjectionLab — Security Vulnerability Audit & Defense Platform",
  description: "Enterprise Security Engineering Platform covering 55 Injection Attack Vectors",
  icons: {
    icon: "/assets/logo_shield.png",
    shortcut: "/assets/logo_shield.png",
    apple: "/assets/logo_shield.png",
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
      className={`${ibmPlexSans.variable} ${ibmPlexMono.variable} h-full antialiased dark`}
    >
      <body className="min-h-full flex flex-col bg-bg-base text-text-primary font-sans selection:bg-brand-primary/30 selection:text-brand-primary">{children}</body>
    </html>
  );
}
