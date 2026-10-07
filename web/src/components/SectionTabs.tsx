import { QUICK_NOTES, SECTION_COLORS, type Section, type SectionColor } from "../pages";

export const PAGE_DRAG = "application/x-kynotes-page";
const SECTION_DRAG = "application/x-kynotes-section";

type Props = {
  sections: Section[]; // already sorted
  current: string;
  busy: boolean;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onRename: (section: Section) => void;
  onColor: (section: Section, color: SectionColor) => void;
  onDelete: (section: Section) => void;
  onMove: (sectionID: string, index: number) => void;
  onDropPage: (pageID: string, sectionID: string) => void;
};

export function SectionTabs({ sections, current, busy, onSelect, onCreate, onRename, onColor, onDelete, onMove, onDropPage }: Props) {
  const accept = (event: React.DragEvent) => {
    const types = event.dataTransfer.types;
    if (types.includes(PAGE_DRAG) || types.includes(SECTION_DRAG)) event.preventDefault();
  };
  const drop = (event: React.DragEvent, sectionID: string, index: number) => {
    const page = event.dataTransfer.getData(PAGE_DRAG);
    const section = event.dataTransfer.getData(SECTION_DRAG);
    if (page) onDropPage(page, sectionID);
    else if (section && sectionID !== QUICK_NOTES) onMove(section, index);
    event.preventDefault();
  };
  const close = (id: string) => document.getElementById(`section-menu-${id}`)?.hidePopover();
  const tab = (id: string, title: string, color: SectionColor, index: number, section?: Section) => (
    <li key={id} className="section-tab-item">
      <button
        className={`quiet ky-nav-item section-tab ${current === id ? "selected" : ""}`}
        aria-current={current === id ? "page" : undefined}
        style={{ "--tab-color": `var(--section-${color})` } as React.CSSProperties}
        draggable={Boolean(section)}
        onDragStart={(event) => event.dataTransfer.setData(SECTION_DRAG, id)}
        onDragOver={accept}
        onDrop={(event) => drop(event, id, index)}
        onClick={() => onSelect(id)}
      >
        {title || "Untitled section"}
      </button>
      {section && current === id && (
        <>
          <button className="quiet section-tab-menu" popoverTarget={`section-menu-${id}`} aria-label={`Section options for ${title}`}>⋯</button>
          <div className="section-menu" id={`section-menu-${id}`} popover="auto">
            <button className="quiet" disabled={busy} onClick={() => { close(id); onRename(section); }}>Rename</button>
            <div className="section-colors" role="group" aria-label="Section color">
              {SECTION_COLORS.map((choice) => (
                <button
                  key={choice}
                  className="section-swatch"
                  aria-label={choice}
                  aria-pressed={section.color === choice}
                  style={{ background: `var(--section-${choice})` }}
                  onClick={() => { close(id); onColor(section, choice); }}
                />
              ))}
            </div>
            <button className="quiet" disabled={index === 0} onClick={() => { close(id); onMove(id, index - 1); }}>Move left</button>
            <button className="quiet" disabled={index === sections.length - 1} onClick={() => { close(id); onMove(id, index + 1); }}>Move right</button>
            <button className="quiet danger" onClick={() => { close(id); onDelete(section); }}>Delete section</button>
          </div>
        </>
      )}
    </li>
  );
  return (
    <nav className="section-tabs" aria-label="Sections">
      <ul role="list">
        {sections.map((section, index) => tab(section.id, section.title, section.color, index, section))}
        {tab(QUICK_NOTES, "Quick Notes", "gray", sections.length)}
      </ul>
      <button className="quiet section-add" disabled={busy} onClick={onCreate} aria-label="New section">＋</button>
    </nav>
  );
}
