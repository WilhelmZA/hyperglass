import { MonoField, ASNField, LatencyField, LossField, HostnameField } from './traceroute-fields';

import type { TracerouteCellRenderProps } from '~/types';

interface TracerouteCellProps {
  data: TracerouteCellRenderProps;
  rawData: TracerouteResult;
}

export const TracerouteCell = (props: TracerouteCellProps): JSX.Element => {
  const { data, rawData } = props;
  const cellId = data.column.id as keyof TracerouteHop;
  
  const component = {
    hop_number: <MonoField v={data.value} />,
    ip_address: <MonoField v={data.value} />,
    hostname: <HostnameField hostname={data.value} />,
    loss_pct: <LossField loss={data.value} />,
    sent_count: <MonoField v={data.value} />,
    last_rtt: <LatencyField rtt={data.value} />,
    avg_rtt: <LatencyField rtt={data.value} />,
    best_rtt: <LatencyField rtt={data.value} />,
    worst_rtt: <LatencyField rtt={data.value} />,
    asn: <ASNField asn={data.value} org={data.row.values.org} />,
    org: null, // Hidden, displayed as part of ASN
    prefix: <MonoField v={data.value} />,
    country: <MonoField v={data.value} />,
    rir: <MonoField v={data.value} />,
    allocated: <MonoField v={data.value} />,
    rtt1: null, // Not displayed directly in table
    rtt2: null, // Not displayed directly in table
    rtt3: null, // Not displayed directly in table
  };
  
  return component[cellId] ?? <MonoField v={data.value} />;
};