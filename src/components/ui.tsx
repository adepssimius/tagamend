import Link from "next/link";
import type { Kev, ScanStatus } from "@/lib/db/schema";

/** One colour per severity, used for badges and counts everywhere. */
const SEVERITY_STYLE: Record<string, { badge: string; text: string }> = {
  CRITICAL: {
    badge: "bg-red-600 text-white dark:bg-red-500/90",
    text: "text-red-700 dark:text-red-400",
  },
  HIGH: {
    badge: "bg-orange-500 text-white dark:bg-orange-500/85",
    text: "text-orange-700 dark:text-orange-400",
  },
  MEDIUM: {
    badge: "bg-amber-300 text-amber-950 dark:bg-amber-400/80",
    text: "text-amber-700 dark:text-amber-300",
  },
  LOW: {
    badge: "bg-sky-200 text-sky-950 dark:bg-sky-500/40 dark:text-sky-100",
    text: "text-sky-700 dark:text-sky-300",
  },
  UNKNOWN: {
    badge: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-200",
    text: "text-zinc-600 dark:text-zinc-400",
  },
};
const sevStyle = (s: string) => SEVERITY_STYLE[s] ?? SEVERITY_STYLE.UNKNOWN!;

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-block w-[4.75rem] rounded px-1.5 py-px text-center text-[11px] font-semibold uppercase tracking-wide ${sevStyle(severity).badge}`}
    >
      {severity}
    </span>
  );
}

/** A count in its severity's colour; zero is muted. */
export function SeverityCount({ severity, n }: { severity: string; n: number }) {
  return n > 0 ? (
    <span className={`font-semibold tabular-nums ${sevStyle(severity).text}`}>{n}</span>
  ) : (
    <span className="tabular-nums text-zinc-300 dark:text-zinc-700">0</span>
  );
}

/** The vuln's own link when it is http(s), since it comes from scanner output; otherwise OSV. */
export const externalVulnUrl = (id: string, link: string | null) =>
  link && /^https?:\/\//i.test(link) ? link : `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}
export const cveHref = (id: string) => `/cves/${encodeURIComponent(id)}`;

/** Marks a CVE in CISA's Known Exploited Vulnerabilities catalog. */
export function ExploitedBadge({ kev }: { kev: Kev }) {
  const title = [
    `In CISA's Known Exploited Vulnerabilities catalog since ${kev.date_added}`,
    kev.vulnerability_name,
    kev.known_ransomware ? "Known to be used in ransomware campaigns." : null,
  ]
    .filter(Boolean)
    .join("\n");
  return (
    <span
      title={title}
      className="ml-1.5 inline-block rounded border border-red-600 px-1 text-[10px] font-semibold uppercase leading-4 tracking-wide text-red-700 dark:border-red-500 dark:text-red-400"
    >
      {kev.known_ransomware ? "exploited · ransomware" : "exploited"}
    </span>
  );
}

/** A CVSS base score, coloured by band. */
export function Cvss({ score }: { score: number | null }) {
  if (score == null) return <span className="text-xs text-zinc-400">—</span>;
  const cls =
    score >= 9
      ? "font-semibold text-red-700 dark:text-red-400"
      : score >= 7
        ? "font-semibold text-orange-700 dark:text-orange-400"
        : score >= 4
          ? "text-amber-700 dark:text-amber-300"
          : "text-zinc-500";
  return <span className={`tabular-nums text-xs ${cls}`}>{score.toFixed(1)}</span>;
}

/** Links a vuln id to its page here, plus an external link, and flags known exploitation. */
export function CveLink({ id, link, kev }: { id: string; link: string | null; kev?: Kev | null }) {
  return (
    <span className="whitespace-nowrap">
      <Link href={cveHref(id)} className="font-mono text-xs text-blue-700 hover:underline dark:text-blue-400">
        {id}
      </Link>
      <a
        href={externalVulnUrl(id, link)}
        target="_blank"
        rel="noreferrer noopener"
        title={`${id} on ${hostOf(externalVulnUrl(id, link))}`}
        className="ml-1 text-zinc-400 hover:text-zinc-700 dark:text-zinc-500 dark:hover:text-zinc-200"
      >
        ↗
      </a>
      {kev && <ExploitedBadge kev={kev} />}
    </span>
  );
}

const SCAN_STYLE: Record<ScanStatus, string> = {
  queued: "bg-zinc-200 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-100",
  running: "bg-blue-100 text-blue-800 dark:bg-blue-900/60 dark:text-blue-200",
  done: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-200",
  failed: "bg-red-100 text-red-800 dark:bg-red-900/60 dark:text-red-200",
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return <span className={`rounded px-1.5 py-px text-[11px] font-medium ${SCAN_STYLE[status]}`}>{status}</span>;
}

export function OkBadge({ ok }: { ok: number | null }) {
  if (ok == null) return <span className="rounded bg-blue-100 px-1.5 py-px text-[11px] font-medium text-blue-800 dark:bg-blue-900/60 dark:text-blue-200">running</span>;
  return ok ? (
    <span className="rounded bg-emerald-100 px-1.5 py-px text-[11px] font-medium text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-200">ok</span>
  ) : (
    <span className="rounded bg-red-100 px-1.5 py-px text-[11px] font-medium text-red-800 dark:bg-red-900/60 dark:text-red-200">error</span>
  );
}

/** Relative time, rendered on the server; the exact time is in the tooltip. */
export function Ago({ iso }: { iso: string | null | undefined }) {
  if (!iso) return <span className="text-zinc-400">—</span>;
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  const abs = Math.abs(s);
  const text =
    abs < 60 ? `${abs}s` : abs < 3600 ? `${Math.round(abs / 60)}m` : abs < 86400 ? `${Math.round(abs / 3600)}h` : `${Math.round(abs / 86400)}d`;
  return (
    <time dateTime={iso} title={iso} className="whitespace-nowrap tabular-nums">
      {s >= 0 ? `${text} ago` : `in ${text}`}
    </time>
  );
}

export function ShortDigest({ digest }: { digest: string }) {
  const hex = digest.replace(/^sha256:/, "");
  return (
    <span className="font-mono text-xs text-zinc-500 dark:text-zinc-400" title={digest}>
      {hex.slice(0, 12)}
    </span>
  );
}

/** A plain section with a heading, a count and an optional note. */
export function Section({
  title,
  count,
  note,
  children,
}: {
  title: string;
  count?: number;
  note?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="mt-8">
      <h2 className="text-sm font-semibold">
        {title}
        {count !== undefined && <span className="ml-1.5 font-normal text-zinc-500">{count}</span>}
      </h2>
      {note && <p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">{note}</p>}
      <div className="mt-2">{children}</div>
    </section>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="text-sm text-zinc-500 dark:text-zinc-400">{children}</p>;
}

/** Table styling shared by every page: dense, striped by hover, scrolls sideways when narrow. */
export function Table({ children }: { children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto rounded border border-zinc-200 dark:border-zinc-800">
      <table className="w-full text-left text-sm [&_td]:px-2.5 [&_td]:py-1.5 [&_td]:align-top [&_th]:px-2.5 [&_th]:py-1.5 [&_th]:text-xs [&_th]:font-medium [&_th]:text-zinc-500 dark:[&_th]:text-zinc-400 [&_thead]:bg-zinc-50 dark:[&_thead]:bg-zinc-900 [&_tbody_tr]:border-t [&_tbody_tr]:border-zinc-100 dark:[&_tbody_tr]:border-zinc-800/80 [&_tbody_tr:hover]:bg-zinc-50/70 dark:[&_tbody_tr:hover]:bg-zinc-900/50">
        {children}
      </table>
    </div>
  );
}

export function ErrorText({ children }: { children: React.ReactNode }) {
  return <pre className="whitespace-pre-wrap font-mono text-xs text-red-700 [overflow-wrap:anywhere] dark:text-red-400">{children}</pre>;
}

export const linkClass = "text-blue-700 hover:underline dark:text-blue-400";
export const mutedClass = "text-zinc-500 dark:text-zinc-400";

export function ImageName({ registry, repository }: { registry: string; repository: string }) {
  return (
    <span>
      <span className="text-zinc-400 dark:text-zinc-500">{registry}/</span>
      <span className="font-medium">{repository}</span>
    </span>
  );
}
