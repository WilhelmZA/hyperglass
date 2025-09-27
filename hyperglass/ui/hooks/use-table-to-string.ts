import { useCallback } from 'react';
import dayjs from 'dayjs';
import relativeTimePlugin from 'dayjs/plugin/relativeTime';
import utcPlugin from 'dayjs/plugin/utc';
import { useConfig } from '~/context';
import { isStructuredOutput, isBGPStructuredOutput, isTracerouteStructuredOutput } from '~/types';

type TableToStringFormatter =
  | ((v: string) => string)
  | ((v: number) => string)
  | ((v: number[]) => string)
  | ((v: string[]) => string)
  | ((v: boolean) => string);

interface TableToStringFormatted {
  age: (v: number) => string;
  active: (v: boolean) => string;
  as_path: (v: number[]) => string;
  communities: (v: string[]) => string;
  rpki_state: (v: number, n: RPKIState) => string;
}

dayjs.extend(relativeTimePlugin);
dayjs.extend(utcPlugin);

function formatAsPath(path: number[]): string {
  return path.join(' → ');
}

function formatCommunities(comms: string[]): string {
  const commsStr = comms.map(c => `      - ${c}`);
  return `\n ${commsStr.join('\n')}`;
}

function formatBool(val: boolean): string {
  let fmt = '';
  if (val === true) {
    fmt = 'yes';
  } else if (val === false) {
    fmt = 'no';
  }
  return fmt;
}

function formatTime(val: number): string {
  const now = dayjs.utc();
  const then = now.subtract(val, 'second');
  const timestamp = then.toString().replace('GMT', 'UTC');
  const relative = now.to(then, true);
  return `${relative} (${timestamp})`;
}

/**
 * Get a function to convert table data to string, for use in the copy button component.
 */
export function useTableToString(
  target: string[],
  data: QueryResponse | undefined,
  ...deps: unknown[]
): () => string {
  const { web, parsedDataFields, messages } = useConfig();

  function formatRpkiState(val: number): string {
    const rpkiStates = [
      web.text.rpkiInvalid,
      web.text.rpkiValid,
      web.text.rpkiUnknown,
      web.text.rpkiUnverified,
    ];
    return rpkiStates[val];
  }

  const tableFormatMap = {
    age: formatTime,
    active: formatBool,
    as_path: formatAsPath,
    communities: formatCommunities,
    rpki_state: formatRpkiState,
  };

  function isFormatted(key: string): key is keyof TableToStringFormatted {
    return key in tableFormatMap;
  }

  function getFmtFunc(accessor: keyof Route): TableToStringFormatter {
    if (isFormatted(accessor)) {
      return tableFormatMap[accessor];
    }
    return String;
  }

  function doFormat(target: string[], data: QueryResponse | undefined): string {
    let result = messages.noOutput;
    try {
      if (typeof data !== 'undefined' && isStructuredOutput(data)) {
        
        // Handle BGP data
        if (isBGPStructuredOutput(data)) {
          // Check if this is BGP data with routes
          if (!('routes' in data.output) || !Array.isArray(data.output.routes)) {
            return messages.noOutput; // Not BGP data, return early
          }
          
          const tableStringParts = [
            `Routes For: ${target.join(', ')}`,
            `Timestamp: ${data.timestamp} UTC`,
          ];
          for (const route of data.output.routes) {
            for (const field of parsedDataFields) {
              const [header, accessor, align] = field;
              if (align !== null) {
                let value = route[accessor];
                
                // Handle fields that should be hidden when empty/not available
                if ((accessor === 'source_rid' || accessor === 'age') && 
                    (value === null || value === undefined || 
                     (typeof value === 'string' && value.trim() === '') ||
                     (accessor === 'age' && value === -1))) {
                  continue; // Skip this field entirely
                }
                
                const fmtFunc = getFmtFunc(accessor) as (v: typeof value) => string;
                value = fmtFunc(value);
                if (accessor === 'prefix') {
                  tableStringParts.push(`  - ${header}: ${value}`);
                } else {
                  tableStringParts.push(`    - ${header}: ${value}`);
                }
              }
            }
          }
          result = tableStringParts.join('\n');
        }
        
        // Handle Traceroute data
        else if (isTracerouteStructuredOutput(data)) {
          if (!('hops' in data.output) || !Array.isArray(data.output.hops)) {
            return messages.noOutput; // Not traceroute data, return early
          }
          
          const formatRTT = (rtt: number | null | undefined): string => {
            if (rtt === null || rtt === undefined) return '*';
            return `${rtt.toFixed(1)}ms`;
          };
          
          const formatIP = (hop: any): string => {
            if (hop.display_ip) return hop.display_ip; // For truncated IPv6
            if (hop.ip_address) return hop.ip_address;
            return '*';
          };
          
          const formatASN = (hop: any): string => {
            if (hop.asn) return `AS${hop.asn}`;
            return '*';
          };
          
          // Create a nicely formatted text table
          const header = `Traceroute to ${data.output.target} from ${data.output.source}`;
          const timestamp = `Timestamp: ${data.timestamp} UTC`;
          const separator = '=' .repeat(header.length);
          
          const tableLines = [
            header,
            timestamp,
            separator,
            '',
            'Hop  IP Address             ASN      Loss  Sent  Last     AVG      Best     Worst',
            '-' .repeat(80),
          ];
          
          for (const hop of data.output.hops) {
            const hopNum = hop.hop_number.toString().padEnd(4);
            const ipAddr = formatIP(hop).padEnd(22);
            const asn = formatASN(hop).padEnd(8);
            const loss = `${hop.loss_pct || 0}%`.padEnd(5);
            const sent = (hop.sent_count || 0).toString().padEnd(5);
            const last = formatRTT(hop.last_rtt).padEnd(8);
            const avg = formatRTT(hop.avg_rtt).padEnd(8);
            const best = formatRTT(hop.best_rtt).padEnd(8);
            const worst = formatRTT(hop.worst_rtt);
            
            tableLines.push(`${hopNum} ${ipAddr} ${asn} ${loss} ${sent} ${last} ${avg} ${best} ${worst}`);
          }
          
          result = tableLines.join('\n');
        }
      }
      return result;
    } catch (err) {
      console.error(err);
      let error = String(err);
      if (err instanceof Error) {
        error = err.message;
      }
      return `An error occurred while parsing the output: '${error}'`;
    }
  }
  const formatCallback = useCallback(doFormat, [target, data, doFormat]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  return useCallback(() => formatCallback(target, data), [target, data, formatCallback, ...deps]);
}
