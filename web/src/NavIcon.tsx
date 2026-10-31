import { createElement, useId } from "react";

// Icon node data from Lucide (https://lucide.dev), ISC License, Copyright (c) Lucide Icons and Contributors.
// The same glyphs KyCalendar's navigation draws through lucide-react, without the dependency.
type Node = [tag: string, attributes: Record<string, string>];
const icons = {
  notebook: [["path", {"d": "M2 6h4"}],["path", {"d": "M2 10h4"}],["path", {"d": "M2 14h4"}],["path", {"d": "M2 18h4"}],["rect", {"width": "16", "height": "20", "x": "4", "y": "2", "rx": "2"}],["path", {"d": "M16 2v20"}]], // notebook
  work: [["polyline", {"points": "22 12 16 12 14 15 10 15 8 12 2 12"}],["path", {"d": "M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"}]], // inbox
  team: [["path", {"d": "M18 21a8 8 0 0 0-16 0"}],["circle", {"cx": "10", "cy": "8", "r": "5"}],["path", {"d": "M22 20c0-3.37-2-6.5-4-8a5 5 0 0 0-.45-8.3"}]], // users-round
  plus: [["path", {"d": "M5 12h14"}],["path", {"d": "M12 5v14"}]], // plus
  chevron: [["path", {"d": "m6 9 6 6 6-6"}]], // chevron-down
  check: [["path", {"d": "M20 6 9 17l-5-5"}]], // check
  more: [["circle", {"cx": "12", "cy": "12", "r": "1"}],["circle", {"cx": "19", "cy": "12", "r": "1"}],["circle", {"cx": "5", "cy": "12", "r": "1"}]], // ellipsis
  settings: [["path", {"d": "M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915"}],["circle", {"cx": "12", "cy": "12", "r": "3"}]], // settings
  palette: [["path", {"d": "M12 22a1 1 0 0 1 0-20 10 9 0 0 1 10 9 5 5 0 0 1-5 5h-2.25a1.75 1.75 0 0 0-1.4 2.8l.3.4a1.75 1.75 0 0 1-1.4 2.8z"}],["circle", {"cx": "13.5", "cy": "6.5", "r": ".5", "fill": "currentColor"}],["circle", {"cx": "17.5", "cy": "10.5", "r": ".5", "fill": "currentColor"}],["circle", {"cx": "6.5", "cy": "12.5", "r": ".5", "fill": "currentColor"}],["circle", {"cx": "8.5", "cy": "7.5", "r": ".5", "fill": "currentColor"}]], // palette
  signout: [["path", {"d": "m16 17 5-5-5-5"}],["path", {"d": "M21 12H9"}],["path", {"d": "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"}]], // log-out
  signin: [["path", {"d": "m10 17 5-5-5-5"}],["path", {"d": "M15 12H3"}],["path", {"d": "M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"}]], // log-in
  menu: [["path", {"d": "M4 5h16"}],["path", {"d": "M4 12h16"}],["path", {"d": "M4 19h16"}]], // menu
  notes: [["path", {"d": "M2 6h4"}],["path", {"d": "M2 10h4"}],["path", {"d": "M2 14h4"}],["path", {"d": "M2 18h4"}],["rect", {"width": "16", "height": "20", "x": "4", "y": "2", "rx": "2"}],["path", {"d": "M9.5 8h5"}],["path", {"d": "M9.5 12H16"}],["path", {"d": "M9.5 16H14"}]], // notebook-text
  users: [["path", {"d": "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"}],["path", {"d": "M16 3.128a4 4 0 0 1 0 7.744"}],["path", {"d": "M22 21v-2a4 4 0 0 0-3-3.87"}],["circle", {"cx": "9", "cy": "7", "r": "4"}]], // users
  sso: [["path", {"d": "M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"}],["circle", {"cx": "16.5", "cy": "7.5", "r": ".5", "fill": "currentColor"}]], // key-round
  backups: [["rect", {"width": "20", "height": "5", "x": "2", "y": "3", "rx": "1"}],["path", {"d": "M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8"}],["path", {"d": "M10 12h4"}]], // archive
  audit: [["path", {"d": "M15 12h-5"}],["path", {"d": "M15 8h-5"}],["path", {"d": "M19 17V5a2 2 0 0 0-2-2H4"}],["path", {"d": "M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"}]], // scroll-text
  server: [["rect", {"width": "20", "height": "8", "x": "2", "y": "2", "rx": "2", "ry": "2"}],["rect", {"width": "20", "height": "8", "x": "2", "y": "14", "rx": "2", "ry": "2"}],["line", {"x1": "6", "x2": "6.01", "y1": "6", "y2": "6"}],["line", {"x1": "6", "x2": "6.01", "y1": "18", "y2": "18"}]], // server
  account: [["circle", {"cx": "12", "cy": "8", "r": "5"}],["path", {"d": "M20 21a8 8 0 0 0-16 0"}]], // user-round
  close: [["path", {"d": "M18 6 6 18"}],["path", {"d": "m6 6 12 12"}]], // x
  back: [["path", {"d": "m15 18-6-6 6-6"}]], // chevron-left
  search: [["path", {"d": "m21 21-4.34-4.34"}],["circle", {"cx": "11", "cy": "11", "r": "8"}]], // search
  h1: [["path", {"d": "M4 12h8"}],["path", {"d": "M4 18V6"}],["path", {"d": "M12 18V6"}],["path", {"d": "m17 12 3-2v8"}]], // heading-1
  h2: [["path", {"d": "M4 12h8"}],["path", {"d": "M4 18V6"}],["path", {"d": "M12 18V6"}],["path", {"d": "M21 18h-4c0-4 4-3 4-6 0-1.5-2-2.5-4-1"}]], // heading-2
  h3: [["path", {"d": "M4 12h8"}],["path", {"d": "M4 18V6"}],["path", {"d": "M12 18V6"}],["path", {"d": "M17.5 10.5c1.7-1 3.5 0 3.5 1.5a2 2 0 0 1-2 2"}],["path", {"d": "M17 17.5c2 1.5 4 .3 4-1.5a2 2 0 0 0-2-2"}]], // heading-3
  bold: [["path", {"d": "M6 12h9a4 4 0 0 1 0 8H7a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h7a4 4 0 0 1 0 8"}]], // bold
  italic: [["line", {"x1": "19", "x2": "10", "y1": "4", "y2": "4"}],["line", {"x1": "14", "x2": "5", "y1": "20", "y2": "20"}],["line", {"x1": "15", "x2": "9", "y1": "4", "y2": "20"}]], // italic
  bullets: [["path", {"d": "M3 5h.01"}],["path", {"d": "M3 12h.01"}],["path", {"d": "M3 19h.01"}],["path", {"d": "M8 5h13"}],["path", {"d": "M8 12h13"}],["path", {"d": "M8 19h13"}]], // list
  numbers: [["path", {"d": "M11 5h10"}],["path", {"d": "M11 12h10"}],["path", {"d": "M11 19h10"}],["path", {"d": "M4 4h1v5"}],["path", {"d": "M4 9h2"}],["path", {"d": "M6.5 20H3.4c0-1 2.6-1.925 2.6-3.5a1.5 1.5 0 0 0-2.6-1.02"}]], // list-ordered
  checklist: [["path", {"d": "M13 5h8"}],["path", {"d": "M13 12h8"}],["path", {"d": "M13 19h8"}],["path", {"d": "m3 17 2 2 4-4"}],["path", {"d": "m3 7 2 2 4-4"}]], // list-checks
  link: [["path", {"d": "M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"}],["path", {"d": "M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"}]], // link
  code: [["path", {"d": "m18 16 4-4-4-4"}],["path", {"d": "m6 8-4 4 4 4"}],["path", {"d": "m14.5 4-5 16"}]], // code-xml
  draw: [["path", {"d": "M13 21h8"}],["path", {"d": "M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"}]], // pen-line
} satisfies Record<string, Node[]>;
export type IconName = keyof typeof icons;

/** Line icons at the suite's 16px and lucide's stroke of 2. */
export function NavIcon({ name }: { name: IconName }) {
  return (
    <svg className="nav-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {(icons[name] as Node[]).map(([tag, attributes], index) => createElement(tag, { key: index, ...attributes }))}
    </svg>
  );
}

/**
 * The KyNotes mark as theme colours: an ink tile with the icon's light notebook cut from app-icon.png
 * (thresholded into a mask) in the page colour. Light themes match the PNG; dark themes invert it.
 */
export function AppMark({ size }: { size: number }) {
  const id = useId().replace(/[^\w-]/g, "");
  return (
    <svg className="app-mark" width={size} height={size} viewBox="0 0 256 256" aria-hidden="true">
      <filter id={`${id}f`}><feColorMatrix type="matrix" values="0 0 0 0 1 0 0 0 0 1 0 0 0 0 1 .55 .55 .55 0 -.33" /></filter>
      <mask id={`${id}m`}><image href="/app-icon.png" width="256" height="256" filter={`url(#${id}f)`} /></mask>
      <rect className="app-mark-tile" width="256" height="256" rx="44" />
      <rect className="app-mark-glyph" width="256" height="256" mask={`url(#${id}m)`} />
    </svg>
  );
}
