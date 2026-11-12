import { gzipSync } from "node:zlib";

/** A minimal ustar writer, enough to build GitHub-shaped tarballs in tests. */
export function header(name: string, size: number, type: string): Buffer {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0);
  h.write("0000644\0", 100);
  h.write(size.toString(8).padStart(11, "0") + "\0", 124);
  h.write(type, 156);
  h.write("ustar\0", 257);
  h.write("00", 263);
  h.fill(" ", 148, 156);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, "0") + "\0 ", 148);
  return h;
}
export function entry(name: string, body: string, type = "0"): Buffer[] {
  const data = Buffer.from(body);
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return [header(name, data.length, type), data, pad];
}
export function pax(path: string): Buffer[] {
  const rec = (s: string) => {
    let len = s.length + 3;
    while (`${len} ${s}\n`.length !== len) len = `${len} ${s}\n`.length;
    return `${len} ${s}\n`;
  };
  return entry("PaxHeader", rec(`path=${path}`), "x");
}


/** A GitHub-shaped tarball: everything under one top-level directory. */
export function repoTarball(files: Record<string, string>): Uint8Array {
  const top = "owner-repo-abc123/";
  return gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => entry(`${top}${p}`, c)), Buffer.alloc(1024)]));
}
