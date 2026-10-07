import { getStroke } from "perfect-freehand";

/** Pressure-aware outline of a flat [x, y, pressure, ...] stroke as an SVG path. */
export function strokePath(points: number[], size: number, highlighter: boolean): string {
  const input: number[][] = [];
  for (let i = 0; i + 2 < points.length; i += 3) input.push([points[i], points[i + 1], points[i + 2]]);
  if (!input.length) return "";
  const outline = getStroke(input, {
    size,
    thinning: highlighter ? 0 : 0.6,
    smoothing: 0.5,
    streamline: 0.5,
    simulatePressure: false,
    last: true,
  });
  if (!outline.length) return "";
  return `M${outline.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join("L")}Z`;
}
