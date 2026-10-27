import { useEffect, useState } from 'react';

// Minimal hash router: #/path/segments?query — no dependency needed.

export interface Route { path: string[]; query: URLSearchParams; }

function parse(): Route {
  const raw = window.location.hash.replace(/^#/, '') || '/overview';
  const [p, q = ''] = raw.split('?');
  return { path: p.split('/').filter(Boolean).map(decodeURIComponent), query: new URLSearchParams(q) };
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(parse);
  useEffect(() => {
    const on = () => setRoute(parse());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return route;
}

export function href(...segments: string[]): string {
  return '#/' + segments.map(encodeURIComponent).join('/');
}

export function navigate(...segments: string[]): void {
  window.location.hash = href(...segments).slice(1);
}
