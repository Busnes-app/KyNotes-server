/**
 * Notebook loads where only the newest may finish. Each begin() supersedes every earlier ticket,
 * a second load of the same notebook included (an automatic load plus a click).
 */
export function loadGate() {
  let latest = 0;
  return {
    begin() {
      const ticket = ++latest;
      return { superseded: () => latest !== ticket };
    },
  };
}
