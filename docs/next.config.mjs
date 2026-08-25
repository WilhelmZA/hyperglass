import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import nextra from "nextra";

function copyChangelog() {
    const dir = path.dirname(fileURLToPath(import.meta.url));
    const src = path.resolve(dir, "..", "CHANGELOG.md");
    const data = fs.readFileSync(src);
    const replaced = data.toString().replace("# Changelog\n\n", "");
    const dst = path.resolve(dir, "content", "changelog.mdx");
    fs.writeFileSync(dst, replaced);
}

copyChangelog();

/**
 * @type {import('next').NextConfig}
 */
const config = {
    images: {
        unoptimized: true,
    },
    output: "export",
};

export default nextra({})(config);
