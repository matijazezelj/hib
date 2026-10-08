// Small stroke icon set (24px grid, inline SVG): no icon font or CDN, nothing fetched.
const PATHS: Record<string, string> = {
  shield: "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z",
  "shield-check": "M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z M8.5 12l2.5 2.5 4.5-5",
  lock: "M6 11h12v9H6z M8.5 11V8a3.5 3.5 0 0 1 7 0v3",
  send: "M4 12l16-8-6 16-2.5-6.5L4 12z",
  plus: "M12 5v14 M5 12h14",
  stop: "M7 7h10v10H7z",
  "chevron-down": "M6 9l6 6 6-6",
  "chevron-right": "M9 6l6 6-6 6",
  eye: "M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z M12 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z",
  check: "M5 12.5l4.5 4.5L19 7.5",
  x: "M6 6l12 12 M18 6L6 18",
  "arrow-up": "M12 19V5 M6 11l6-6 6 6",
  gauge: "M4 15a8 8 0 1 1 16 0 M12 15l4-5",
  chart: "M5 19V9 M10 19V5 M15 19v-7 M20 19v-4",
  clock: "M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17z M12 7.5V12l3 2",
  file: "M7 3h7l4 4v14H7z M14 3v4h4",
  folder: "M3.5 6.5a1.5 1.5 0 0 1 1.5-1.5h4l2 2.5h8a1.5 1.5 0 0 1 1.5 1.5v8.5a1.5 1.5 0 0 1-1.5 1.5H5a1.5 1.5 0 0 1-1.5-1.5z",
  table: "M4 5h16v14H4z M4 10h16 M4 15h16 M10 5v14",
  play: "M8 5l11 7-11 7z",
  sparkles: "M12 4l1.8 4.2L18 10l-4.2 1.8L12 16l-1.8-4.2L6 10l4.2-1.8z M18.5 15.5l.8 1.7 1.7.8-1.7.8-.8 1.7-.8-1.7-1.7-.8 1.7-.8z",
  swords: "M14.5 4H20v5.5L9 20.5 3.5 15z M4 20l3-3 M15 15l5 5 M18 13l-5 5",
  "thumbs-up": "M7 21V10 M7 10l4-7c1.5 0 2.5 1 2.5 2.5V9h5a2 2 0 0 1 2 2.3l-1.3 7.5A2.5 2.5 0 0 1 16.7 21H7 M3 10h4v11H3z",
  "thumbs-down": "M17 3v11 M17 14l-4 7c-1.5 0-2.5-1-2.5-2.5V15h-5a2 2 0 0 1-2-2.3L4.8 5.2A2.5 2.5 0 0 1 7.3 3H17 M21 14h-4V3h4z",
  alert: "M12 4l9 16H3z M12 10v4 M12 17h.01",
  code: "M8 8l-4 4 4 4 M16 8l4 4-4 4 M13.5 5l-3 14",
  search: "M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13z M15.5 15.5L20 20",
  route: "M6 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4z M18 9a2 2 0 1 0 0-4 2 2 0 0 0 0 4z M6 15V9a4 4 0 0 1 4-4h6 M8 19h6a4 4 0 0 0 4-4v-4",
  wand: "M4 20L15 9 M13 7l4 4 M17 3v3 M15.5 4.5h3 M20 8v2 M19 9h2",
};

export function Icon({ name, size = 16, className = "" }: { name: keyof typeof PATHS | string; size?: number; className?: string }) {
  return (
    <svg className={`icon ${className}`} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {(PATHS[name] ?? "").split(" M").map((d, i) => <path key={i} d={i ? `M${d}` : d} />)}
    </svg>
  );
}
