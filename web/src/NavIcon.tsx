const paths = {
  notebook: "M6 3h12a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm2 0v18m4-13h4m-4 4h4",
  work: "M4 4h16v16H4V4Zm0 10h4l2 3h4l2-3h4",
  team: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m20 0v-2a4 4 0 0 0-3-3.87M13 3.13a4 4 0 0 1 0 7.75M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z",
  plus: "M12 5v14M5 12h14",
  rename: "m16 3 5 5L9 20l-6 1 1-6L16 3Zm-3 3 5 5",
  export: "M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5",
  chevron: "m6 9 6 6 6-6",
};

export function NavIcon({ name }: { name: keyof typeof paths }) {
  return <svg className="nav-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]} /></svg>;
}
