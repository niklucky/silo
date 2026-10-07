import { defineConfig } from "wxt";

// Both ids are baked into the native messaging manifests that
// `secret browser install` writes (crates/cli/src/browser.rs). Change both or neither.
const FIREFOX_ID = "{a0c28bb5-d123-45d0-bc03-db1ac9a0a61d}";
// Public half of a throwaway RSA key. Pinning it gives every unpacked Chrome
// build the same extension id: mhngnkbgjofcmibiepppmjmhdcfmkama.
const CHROME_KEY =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3dzTdFEHqz47TKsDiP8zyYSfkkGooQ1Lexe0TPYJJdP1wtu1Zj8JjelDwtwLufpaw7ij5+lLB9s0HF3TXrH8Afj5sCvwaUQGppFwroc9Ofd7lG0hDxW1nqU8UPCTi8urWkJMBriN0HdwSfJ3TmtmH1E2rY0YyTTihhnrsekqwSFc/KO6KTiSFoxQU+FxS9kFRIqvcKzre8mKV7ED5o5L1uXXD7dNHkO75A8lg1/hb6gEZSd46nJ4T71s6cwVht7HwTosToKVufpYEHNjL4lqguSGVsdAP5qcY73cPXd9JK7JNg2rDoSjAlMQ+AfPDs3h2WGwqw75zUzol4mypgH1NwIDAQAB";

// https://wxt.dev/api/config.html
export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: ({ browser }) => ({
    name: "Secret",
    description:
      "Passwords, env vars and secret files, including HTTP Basic Auth autofill.",
    permissions: [
      "nativeMessaging",
      "storage",
      "webRequest",
      // Firefox answers auth challenges from a blocking listener; Chromium from
      // an asyncBlocking one that needs its own permission.
      ...(browser === "firefox" ? ["webRequestBlocking"] : ["webRequestAuthProvider"]),
    ],
    host_permissions: ["<all_urls>"],
    // The sign-in page a 401 redirects to. Must be reachable from a web navigation.
    web_accessible_resources: [{ resources: ["auth.html"], matches: ["<all_urls>"] }],
    ...(browser === "firefox"
      ? {
          browser_specific_settings: {
            gecko: {
              id: FIREFOX_ID,
              strict_min_version: "115.0",
              data_collection_permissions: { required: ["none"] },
            },
          },
        }
      : { key: CHROME_KEY }),
  }),
});
