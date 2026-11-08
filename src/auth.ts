import NextAuth, { type NextAuthConfig } from "next-auth";
import { redirect } from "next/navigation";
import { getConfig } from "./lib/config";

declare module "next-auth" {
  interface Session {
    user: { name?: string | null; email?: string | null; username?: string; groups?: string[] };
  }
}

/**
 * Generic OIDC (Authelia in the cluster). Authorization code flow with PKCE,
 * confidential client using client_secret_post. Sessions are JWT cookies, so
 * there is no session table.
 *
 * The config is built per request (the function form) so `next build` does not
 * need the OIDC environment.
 */
export const { handlers, auth, signIn, signOut } = NextAuth((): NextAuthConfig => {
  const c = getConfig();
  return {
    trustHost: true,
    secret: c.AUTH_SECRET,
    session: { strategy: "jwt" },
    providers: c.OIDC_ISSUER
      ? [
          {
            id: "oidc",
            name: "Single sign-on",
            type: "oidc",
            issuer: c.OIDC_ISSUER,
            clientId: c.OIDC_CLIENT_ID,
            clientSecret: c.OIDC_CLIENT_SECRET,
            checks: ["pkce", "state"],
            client: { token_endpoint_auth_method: "client_secret_post" },
            authorization: { params: { scope: "openid profile email groups" } },
          },
        ]
      : [],
    callbacks: {
      signIn({ profile }) {
        const allowed = c.OIDC_ALLOWED_GROUPS;
        if (!allowed?.length) return true;
        const groups = (profile?.groups as string[] | undefined) ?? [];
        return groups.some((g) => allowed.includes(g));
      },
      jwt({ token, profile }) {
        if (profile) {
          token.username = (profile.preferred_username as string | undefined) ?? profile.sub ?? undefined;
          token.groups = (profile.groups as string[] | undefined) ?? [];
        }
        return token;
      },
      session({ session, token }) {
        session.user.username = token.username as string | undefined;
        session.user.groups = token.groups as string[] | undefined;
        return session;
      },
    },
  };
});

export interface CurrentUser {
  username: string;
  name: string | null;
}

/**
 * The signed-in user, or a redirect to sign-in. Call this at the top of every
 * page and server action. AUTH_DEV_USER bypasses OIDC outside production.
 */
export async function requireUser(): Promise<CurrentUser> {
  const dev = getConfig().AUTH_DEV_USER;
  if (dev) return { username: dev, name: dev };
  const session = await auth();
  if (!session?.user) redirect("/api/auth/signin");
  return {
    username: session.user.username ?? session.user.email ?? "unknown",
    name: session.user.name ?? null,
  };
}
