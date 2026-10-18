/** Saves content as a file the user downloads; nothing is stored by the page. */
export function downloadFile(name: string, content: string | Blob, type: string): void {
  const url = URL.createObjectURL(typeof content === "string" ? new Blob([content], { type }) : content);
  const link = document.createElement("a");
  link.href = url; link.download = name;
  document.body.append(link); link.click(); link.remove();
  // Revoked after the download has started; revoking in the same tick can cancel it.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
