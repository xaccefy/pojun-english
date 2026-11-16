import type { Metadata } from "next";
import type { ReactNode } from "react";

// The auth pages (sign-in/setup) are the only UI visible on the public internet without
// a password: the document title and visible copy always use a neutral identity with no
// product name — fingerprint resistance for a deployment starts at this layer.
export const metadata: Metadata = {
  title: "Console",
  description: "Sign in",
};

export default function AuthLayout({ children }: { readonly children: ReactNode }) {
  return <>{children}</>;
}
