"use client";

import { useFormStatus } from "react-dom";

/** A form submit button that disables itself while the server action runs. */
export function SubmitButton({ children, pendingText }: { children: React.ReactNode; pendingText: string }) {
  const { pending } = useFormStatus();
  return (
    <button
      type="submit"
      disabled={pending}
      className="rounded border border-zinc-300 bg-white px-2 py-0.5 text-xs font-medium hover:bg-zinc-100 disabled:opacity-50 dark:border-zinc-700 dark:bg-zinc-900 dark:hover:bg-zinc-800"
    >
      {pending ? pendingText : children}
    </button>
  );
}
