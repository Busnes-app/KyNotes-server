import { useId } from "react";

const paths = {
  notebook: "M6 3h12a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm2 0v18m4-13h4m-4 4h4",
  work: "M4 4h16v16H4V4Zm0 10h4l2 3h4l2-3h4",
  team: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m20 0v-2a4 4 0 0 0-3-3.87M13 3.13a4 4 0 0 1 0 7.75M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z",
  plus: "M12 5v14M5 12h14",
  chevron: "m6 9 6 6 6-6",
  check: "M20 6 9 17l-5-5",
  more: "M5 12h.01M12 12h.01M19 12h.01",
  // lucide Settings and Palette, as KyCalendar's navigation draws them.
  settings: "M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915",
  palette: "M12 22a1 1 0 0 1 0-20 10 9 0 0 1 10 9 5 5 0 0 1-5 5h-2.25a1.75 1.75 0 0 0-1.4 2.8l.3.4a1.75 1.75 0 0 1-1.4 2.8z",
  signout: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9",
  signin: "M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3",
};
type Name = keyof typeof paths;
const circles: Partial<Record<Name, Array<[cx: number, cy: number, r: number, filled?: true]>>> = {
  settings: [[12, 12, 3]],
  palette: [[13.5, 6.5, 0.5, true], [17.5, 10.5, 0.5, true], [6.5, 12.5, 0.5, true], [8.5, 7.5, 0.5, true]],
};

/** Line icons at the suite's 16px and lucide's stroke of 2. */
export function NavIcon({ name }: { name: Name }) {
  return (
    <svg className="nav-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={name === "more" ? 3 : 2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={paths[name]} />
      {circles[name]?.map(([cx, cy, r, filled]) => <circle key={`${cx},${cy}`} cx={cx} cy={cy} r={r} fill={filled ? "currentColor" : undefined} />)}
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
