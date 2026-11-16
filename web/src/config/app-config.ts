import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

// The document title and description are a fingerprint surface anyone can grab from
// the public internet without auth (both the root path and the 404 page carry them).
// Keep them neutral; the product name only shows up behind login (visible means
// already authenticated).
export const APP_CONFIG = {
  name: "Pojun",
  version: packageJson.version,
  copyright: `© ${currentYear}, Pojun.`,
  meta: {
    title: "Console",
    description: "Authorized operations console",
  },
};
