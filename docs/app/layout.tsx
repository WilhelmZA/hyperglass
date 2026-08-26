import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Layout, Navbar } from "nextra-theme-docs";
import { getPageMap } from "nextra/page-map";
import "nextra-theme-docs/style.css";

const noIndexFollow = process.env.CF_PAGES_BRANCH !== "main";

export const metadata: Metadata = {
    title: {
        default: "Ultraglass Documentation",
        template: "%s | Ultraglass",
    },
    description: "Documentation for Ultraglass, a network looking glass for operators.",
    openGraph: {
        type: "website",
        siteName: "Ultraglass",
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
                    docsRepositoryBase="https://github.com/WilhelmZA/ultraglass/tree/main/docs"
                    navbar={
                        <Navbar
                            logo={
                                <picture>
                                    <source media="(prefers-color-scheme: dark)" srcSet="/ultraglass-dark.svg" />
                                    <img src="/ultraglass-light.svg" alt="Ultraglass" height="32" />
                                </picture>
                            }
                            projectLink="https://github.com/WilhelmZA/ultraglass"
                        >
                            <a href="https://github.com/WilhelmZA/ultraglass/wiki">Wiki</a>
                        </Navbar>
                    }
                    pageMap={pageMap}
                >
                    {children}
                </Layout>
            </body>
        </html>
    );
}
