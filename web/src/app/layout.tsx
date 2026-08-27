import type { Metadata } from 'next';
// Self-hosted DM Sans (bundled — zero third-party font requests)
import '@fontsource/dm-sans/400.css';
import '@fontsource/dm-sans/500.css';
import '@fontsource/dm-sans/600.css';
import '@fontsource/dm-sans/700.css';
import '@/spa/theme.css';

export const metadata: Metadata = {
  title: 'Mailtrace — Email Threat Intelligence',
  description: 'Email threat detection, geolocation and forensic intelligence.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div id="root">{children}</div>
      </body>
    </html>
  );
}
