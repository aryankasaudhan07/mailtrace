import type { Metadata, Viewport } from 'next';
// Self-hosted fonts (bundled — zero third-party font requests).
// Onest is the primary UI/display face (elegant grotesque); DM Sans is kept as
// a fallback weight source for any component that still references it.
import '@fontsource-variable/onest/index.css';
import '@fontsource/dm-sans/400.css';
import '@fontsource/dm-sans/500.css';
import '@fontsource/dm-sans/600.css';
import '@fontsource/dm-sans/700.css';
import '@/spa/theme.css';

export const metadata: Metadata = {
  title: 'Mailtrace — Email Threat Intelligence',
  description: 'Email threat detection, geolocation and forensic intelligence.',
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
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
