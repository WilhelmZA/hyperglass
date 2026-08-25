import type { CellProps } from 'react-table';

export interface TableColumn<T extends object = Route> {
  Header: string;
  accessor: keyof T;
  align: string;
  hidden: boolean;
}

export interface TracerouteTableColumn {
  Header: string;
  accessor: keyof TracerouteHop;
  align: string;
  hidden: boolean;
}

export type CellRenderProps<T extends object = RouteField> = {
  column: CellProps<T>['column'];
  row: CellProps<T>['row'];
  value: CellProps<T>['value'];
};

export type TracerouteCellRenderProps = CellRenderProps<TracerouteHopField>;
