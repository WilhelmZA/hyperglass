import { Table, Thead, Tbody, Tr, Th, Td, Flex, Box } from '@chakra-ui/react';
import { TracerouteCell } from './traceroute-cell';
import { useColorValue } from '~/hooks';

import type { FlexProps } from '@chakra-ui/react';
import type { TracerouteCellRenderProps } from '~/types';

type TracerouteTableProps = Swap<FlexProps, 'children', TracerouteResult>;

// Column definition for the traceroute table
// Format: "Hop | IP | HostName (reverse dns) | ASN | Loss | Sent | Last | AVG | BEST | Worst"
const columns = [
  { key: 'hop_number', header: 'Hop', align: 'center' as const, width: '80px' },
  { key: 'ip_address', header: 'IP Address', align: 'left' as const, width: '160px' },
  { key: 'hostname', header: 'Hostname', align: 'left' as const, width: '280px' },
  { key: 'asn', header: 'ASN', align: 'center' as const, width: '100px' },
  { key: 'loss_pct', header: 'Loss', align: 'center' as const, width: '80px' },
  { key: 'sent_count', header: 'Sent', align: 'center' as const, width: '80px' },
  { key: 'last_rtt', header: 'Last', align: 'right' as const, width: '90px' },
  { key: 'avg_rtt', header: 'AVG', align: 'right' as const, width: '90px' },
  { key: 'best_rtt', header: 'Best', align: 'right' as const, width: '90px' },
  { key: 'worst_rtt', header: 'Worst', align: 'right' as const, width: '90px' },
] as const;

export const TracerouteTable = (props: TracerouteTableProps): JSX.Element => {
  const { children: data, ...rest } = props;
  const borderColor = useColorValue('gray.200', 'gray.700');
  const headerBg = useColorValue('gray.50', 'gray.800');

  return (
    <Flex my={8} justify="center" w="100%" {...rest}>
      <Box w="100%" overflowX="auto">
        <Table variant="simple" size="sm" w="100%" minW="1200px">
          <Thead bg={headerBg}>
            <Tr>
              {columns.map((column) => (
                <Th
                  key={column.key}
                  textAlign={column.align}
                  fontSize="xs"
                  fontWeight="semibold"
                  textTransform="uppercase"
                  letterSpacing="wide"
                  w={column.width}
                  border="1px"
                  borderColor={borderColor}
                >
                  {column.header}
                </Th>
              ))}
            </Tr>
        </Thead>
        <Tbody>
          {data.hops.map((hop, index) => (
            <Tr key={hop.hop_number || index}>
              {columns.map((column) => {
                const cellData = {
                  column: { id: column.key },
                  row: { values: hop },
                  value: hop[column.key as keyof TracerouteHop],
                } as TracerouteCellRenderProps;

                return (
                  <Td 
                    key={column.key} 
                    textAlign={column.align} 
                    py={2}
                    minW={column.width}
                    border="1px"
                    borderColor={borderColor}
                  >
                    <TracerouteCell data={cellData} rawData={data} />
                  </Td>
                );
              })}
            </Tr>
          ))}
        </Tbody>
      </Table>
      </Box>
    </Flex>
  );
};