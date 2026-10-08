import { QUICK_NOTES, SECTION_COLORS, type Group, type Section, type SectionColor } from "../pages";

export const PAGE_DRAG = "application/x-kynotes-page";
const SECTION_DRAG = "application/x-kynotes-section";
const ROOT = "root"; // select value for the notebook root; object IDs never match it

type Kind = "section" | "group";
type Props = {
  sections: Section[]; // the current group's sections, sorted
  groups: Group[]; // the current group's child groups, sorted
  path: Array<{ id: string | undefined; title: string }>; // notebook first, current group last
  current: string;
  busy: boolean;
  /** Sections and groups written before the notebook was shared; labelled as not verified. */
  unverified: ReadonlySet<string>;
  canCreateGroup: boolean;
  moveTargets: (kind: Kind, id: string) => Array<{ id: string; label: string }>;
  onSelect: (id: string) => void;
  onCreate: (kind: Kind) => void;
  onRename: (kind: Kind, entry: Section | Group) => void;
  onColor: (kind: Kind, entry: Section | Group, color: SectionColor) => void;
  onDelete: (section: Section) => void;
  onDeleteGroup: (group: Group) => void;
  onMove: (kind: Kind, id: string, index: number) => void;
  onMoveIntoGroup: (kind: Kind, id: string, target: string | undefined) => void;
  onOpenGroup: (id: string | undefined) => void;
  onDropPage: (pageID: string, sectionID: string) => void;
};

export function SectionTabs(props: Props) {
  const { sections, groups, path, current, busy, onSelect, onDropPage } = props;
  const here = path[path.length - 1]?.id;
  const atRoot = here === undefined;
  const accept = (event: React.DragEvent, types: string[]) => {
    if (types.some((type) => event.dataTransfer.types.includes(type))) event.preventDefault();
  };
  const drop = (event: React.DragEvent, sectionID: string, index: number) => {
    const page = event.dataTransfer.getData(PAGE_DRAG);
    const section = event.dataTransfer.getData(SECTION_DRAG);
    if (page) onDropPage(page, sectionID);
    else if (section && sectionID !== QUICK_NOTES) props.onMove("section", section, index);
    event.preventDefault();
  };
  const close = (menu: string) => document.getElementById(menu)?.hidePopover();
  const menu = (kind: Kind, entry: Section | Group, index: number, count: number, remove: () => void) => {
    const id = `${kind}-menu-${entry.id}`;
    const targets = props.moveTargets(kind, entry.id).filter((target) => target.id !== here);
    return (
      <div className="section-menu" id={id} popover="auto" style={kind === "group" ? { positionAnchor: `--group-${entry.id}` } : undefined}>
        <button className="quiet" disabled={busy} onClick={() => { close(id); props.onRename(kind, entry); }}>Rename</button>
        <div className="section-colors" role="group" aria-label={kind === "section" ? "Section color" : "Group color"}>
          {SECTION_COLORS.map((choice) => (
            <button
              key={choice}
              className="section-swatch"
              aria-label={choice}
              aria-pressed={entry.color === choice}
              style={{ background: `var(--section-${choice})` }}
              disabled={busy}
              onClick={() => { close(id); props.onColor(kind, entry, choice); }}
            />
          ))}
        </div>
        <button className="quiet" disabled={busy || index === 0} onClick={() => { close(id); props.onMove(kind, entry.id, index - 1); }}>Move left</button>
        <button className="quiet" disabled={busy || index === count - 1} onClick={() => { close(id); props.onMove(kind, entry.id, index + 1); }}>Move right</button>
        <select
          aria-label="Move into group"
          value=""
          disabled={busy || (atRoot && !targets.length)}
          onChange={(event) => { close(id); props.onMoveIntoGroup(kind, entry.id, event.target.value === ROOT ? undefined : event.target.value); }}
        >
          <option value="" disabled>Move into group…</option>
          {!atRoot && <option value={ROOT}>Top level of {path[0].title}</option>}
          {targets.map((target) => <option key={target.id} value={target.id}>{target.label}</option>)}
        </select>
        <button className="quiet danger" disabled={busy} onClick={() => { close(id); remove(); }}>{kind === "section" ? "Delete section" : "Delete group"}</button>
      </div>
    );
  };
  const tab = (id: string, title: string, color: SectionColor, index: number, section?: Section) => (
    <li key={id} className="section-tab-item">
      <button
        className={`quiet ky-nav-item section-tab ${current === id ? "selected" : ""}`}
        aria-current={current === id ? "page" : undefined}
        style={{ "--tab-color": `var(--section-${color})` } as React.CSSProperties}
        draggable={Boolean(section) && !busy}
        onDragStart={(event) => event.dataTransfer.setData(SECTION_DRAG, id)}
        onDragOver={(event) => accept(event, [PAGE_DRAG, SECTION_DRAG])}
        onDrop={(event) => drop(event, id, index)}
        onClick={() => onSelect(id)}
      >
        {title || "Untitled section"}
        {props.unverified.has(id) && <em title="Written before this notebook was shared; not end-to-end verified."> · not verified</em>}
      </button>
      {section && current === id && (
        <>
          <button className="quiet section-tab-menu" popoverTarget={`section-menu-${id}`} aria-label={`Section options for ${title || "Untitled section"}`}>⋯</button>
          {menu("section", section, index, sections.length, () => props.onDelete(section))}
        </>
      )}
    </li>
  );
  const groupTab = (group: Group, index: number) => (
    <li key={group.id} className="section-tab-item">
      <button
        className="quiet ky-nav-item section-tab group-tab"
        style={{ "--tab-color": `var(--section-${group.color})` } as React.CSSProperties}
        onDragOver={(event) => accept(event, [SECTION_DRAG])}
        onDrop={(event) => {
          const section = event.dataTransfer.getData(SECTION_DRAG);
          if (section) props.onMoveIntoGroup("section", section, group.id);
          event.preventDefault();
        }}
        onClick={() => props.onOpenGroup(group.id)}
      >
        <span aria-hidden="true">📁 </span>{group.title || "Untitled group"}
        {props.unverified.has(group.id) && <em title="Written before this notebook was shared; not end-to-end verified."> · not verified</em>}
      </button>
      <button className="quiet section-tab-menu" style={{ anchorName: `--group-${group.id}` }} popoverTarget={`group-menu-${group.id}`} aria-label={`Group options for ${group.title || "Untitled group"}`}>⋯</button>
      {menu("group", group, index, groups.length, () => props.onDeleteGroup(group))}
    </li>
  );
  return (
    <nav className="section-tabs" aria-label="Sections">
      {!atRoot && (
        <ol className="section-breadcrumb" aria-label="Section groups">
          {path.map((step, index) => (
            <li key={step.id ?? ROOT}>
              <button className="quiet" aria-current={index === path.length - 1 ? "location" : undefined} onClick={() => props.onOpenGroup(step.id)}>
                {step.title}
              </button>
            </li>
          ))}
        </ol>
      )}
      <ul role="list">
        {sections.map((section, index) => tab(section.id, section.title, section.color, index, section))}
        {atRoot && tab(QUICK_NOTES, "Quick Notes", "gray", sections.length)}
        {groups.map(groupTab)}
        {!atRoot && !sections.length && !groups.length && <li className="section-empty">This group is empty. Add a section with ＋.</li>}
      </ul>
      <button className="quiet section-add" disabled={busy} popoverTarget="section-add-menu" aria-label="New section or group">＋</button>
      <div className="section-menu section-add-menu" id="section-add-menu" popover="auto">
        <button className="quiet" disabled={busy} onClick={() => { close("section-add-menu"); props.onCreate("section"); }}>New section</button>
        <button className="quiet" disabled={busy || !props.canCreateGroup} onClick={() => { close("section-add-menu"); props.onCreate("group"); }}>New section group</button>
      </div>
    </nav>
  );
}
