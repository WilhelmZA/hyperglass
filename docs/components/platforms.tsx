import { Code, Table } from "nextra/components";
import platforms from "~/platforms.json";
import { NotSupported } from "./not-supported-icon";
import { Supported } from "./supported-icon";

export const SupportedPlatforms = () => (
    <ul className="nx-mt-2 first:nx-mt-0 ltr:nx-ml-6 rtl:nx-mr-6">
        {platforms.reduce<React.ReactNode[]>((final, platform) => {
            if (platform.native) {
                const element = (
                    <li key={platform.name}>
                        <Supported style={{ display: "inline", marginRight: "0.5rem" }} />
                        {platform.name}
                    </li>
                );
                final.push(element);
            }
            return final;
        }, [])}
    </ul>
);

export const PlatformTable = () => (
    <Table>
        <tbody>
            <tr>
                <th>Platform Keys</th>
                <th>Natively Supported</th>
            </tr>
            {platforms.map((spec) => (
                <tr key={spec.keys.join("--")}>
                    <td>
                        {spec.keys.map((key) => (
                            <Code className="nx-mx-2" key={key}>
                                {key}
                            </Code>
                        ))}
                    </td>
                    <td align="center">{spec.native ? <Supported /> : <NotSupported />}</td>
                </tr>
            ))}
        </tbody>
    </Table>
);
