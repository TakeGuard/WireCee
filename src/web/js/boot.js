try {
  const stored = localStorage.getItem("wirecee.theme");
  if (stored) {
    document.documentElement.dataset.theme = stored;
  } else if (matchMedia("(prefers-color-scheme: light)").matches) {
    document.documentElement.dataset.theme = "light";
  }
} catch {
}
