import { gunzipSync } from "node:zlib";

/**
 * Reads the text files of a gzipped tarball whose paths `keep` accepts.
 *
 * GitHub's tarball endpoint wraps everything in one top-level directory
 * (`owner-repo-<sha>/`); it is stripped, so paths are relative to the repo
 * root. Handles ustar `prefix` and PAX `path` records for long names.
 */
export function readTarGz(gz: Uint8Array, keep: (path: string) => boolean): Map<string, string> {
  const buf = gunzipSync(gz);
  const out = new Map<string, string>();
  let off = 0;
  let paxPath: string | undefined;
  const str = (start: number, len: number) => {
    const b = buf.subarray(start, start + len);
    const nul = b.indexOf(0);
    return b.subarray(0, nul < 0 ? len : nul).toString("utf8");
  };
  while (off + 512 <= buf.length) {
    const name = str(off, 100);
    if (!name && buf[off] === 0) break; // end-of-archive block
    const size = parseInt(str(off + 124, 12).trim() || "0", 8);
    const type = String.fromCharCode(buf[off + 156] || 48);
    const prefix = str(off + 345, 155);
    const dataStart = off + 512;
    const data = buf.subarray(dataStart, dataStart + size);
    off = dataStart + Math.ceil(size / 512) * 512;

    if (type === "x") {
      // PAX extended header for the next entry: "<len> key=value\n" records.
      for (const rec of data.toString("utf8").split("\n")) {
        const m = /^\d+ path=(.*)$/.exec(rec);
        if (m) paxPath = m[1];
      }
      continue;
    }
    if (type === "g") continue; // global PAX header (GitHub puts the commit here)
    const full = paxPath ?? (prefix ? `${prefix}/${name}` : name);
    paxPath = undefined;
    if (type !== "0" && type !== "\0") continue; // regular files only
    const slash = full.indexOf("/");
    const path = slash >= 0 ? full.slice(slash + 1) : full;
    if (path && keep(path)) out.set(path, data.toString("utf8"));
  }
  return out;
}
