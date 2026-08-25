import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Layout } from "nextra-theme-docs";
import { getPageMap } from "nextra/page-map";
import "nextra-theme-docs/style.css";

const noIndexFollow = process.env.CF_PAGES_BRANCH !== "main";

export const metadata: Metadata = {
    metadataBase: new URL("https://hyperglass.dev"),
    title: {
        default: "hyperglass Documentation",
        template: "%s | hyperglass",
    },
    description: "hyperglass Documentation",
    openGraph: {
        type: "website",
        siteName: "hyperglass",
        images: ["/opengraph.jpg"],
    },
    robots: {
        index: !noIndexFollow,
        follow: !noIndexFollow,
    },
};

type RootLayoutProps = Readonly<{ children: ReactNode }>;

export default async function RootLayout({ children }: RootLayoutProps) {
    const pageMap = await getPageMap();

    return (
        <html lang="en" dir="ltr" suppressHydrationWarning>
            <body>
                <Layout
                    docsRepositoryBase="https://github.com/thatmattlove/hyperglass/tree/main/docs"
                    pageMap={pageMap}
                >
                    {children}
                </Layout>
            </body>
        </html>
    );
}
