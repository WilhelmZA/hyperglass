import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo } from 'react';
import { useConfig } from '~/context';
import { fetchWithTimeout } from '~/util';

import { useFormState } from './use-form-state';

import type {
  QueryFunction,
  QueryFunctionContext,
  QueryObserverResult,
  UseQueryOptions,
} from '@tanstack/react-query';
import type { FormQuery } from '~/types';

type LGQueryKey = [string, FormQuery];

type LGQueryOptions = Omit<
  UseQueryOptions<QueryResponse, Response | QueryResponse | Error, QueryResponse, LGQueryKey>,
  | 'queryKey'
  | 'queryFn'
  | 'cacheTime'
  | 'refetchOnWindowFocus'
  | 'refetchInterval'
  | 'refetchOnMount'
>;

/**
 * Custom hook handle submission of a query to the hyperglass backend.
 */
export function useLGQuery(
  query: FormQuery,
  options: LGQueryOptions = {} as LGQueryOptions,
): QueryObserverResult<QueryResponse> {
  const { requestTimeout, cache } = useConfig();
  const controller = useMemo(() => new AbortController(), []);

  const runQuery: QueryFunction<QueryResponse, LGQueryKey> = async (
    ctx: QueryFunctionContext<LGQueryKey>,
  ): Promise<QueryResponse> => {
    const [url, data] = ctx.queryKey;
    const { queryLocation, queryTarget, queryType } = data;
    const res = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          queryLocation,
          queryTarget,
          queryType,
        }),
        mode: 'cors',
      },
      requestTimeout * 1000,
      controller,
    );
    try {
      const data = await res.json();
      return data;
    } catch (err) {
      throw new Error(res.statusText);
    }
  };

  // Cancel any still-running queries on unmount.
  useEffect(
    () => () => {
      controller.abort();
    },
    [controller],
  );

  const queryClient = useQueryClient();
  const result = useQuery<QueryResponse, Response | QueryResponse | Error, QueryResponse, LGQueryKey>({
    queryKey: ['/api/query', query],
    queryFn: runQuery,
    // Don't refetch when window refocuses.
    refetchOnWindowFocus: false,
    // Don't automatically refetch query data (queries should be on-off).
    refetchInterval: false,
    // Don't refetch on component remount.
    refetchOnMount: false,
    ...options,
  });

  useEffect(() => {
    const resultData = result.data;
    const enrichmentId = resultData?.id;
    if (!resultData || !enrichmentId || resultData.enrichment !== 'pending') {
      return undefined;
    }

    const controller = new AbortController();
    let polling = false;
    const poll = async (): Promise<void> => {
      if (polling) {
        return;
      }
      polling = true;
      try {
        const response = await fetch(
          `/api/query/${encodeURIComponent(enrichmentId)}/enrichment`,
          { signal: controller.signal, cache: 'no-store' },
        );
        if (!response.ok) {
          return;
        }

        const update = (await response.json()) as {
          status: QueryResponse['enrichment'] | 'not_found';
          output?: QueryResponse['output'];
        };
        if (update.status === 'not_found') {
          window.clearInterval(interval);
          return;
        }
        if (update.status === 'pending') {
          return;
        }
        const enrichment = update.status;

        const queryKey: LGQueryKey = ['/api/query', query];
        const current = queryClient.getQueryData<QueryResponse>(queryKey);
        if (!current) {
          return;
        }
        const updated = {
          ...current,
          enrichment,
          ...(update.output === undefined ? {} : { output: update.output }),
        };
        queryClient.setQueryData<QueryResponse>(queryKey, updated);
        useFormState.getState().addResponse(query.queryLocation, updated);
      } catch (error) {
        if (!controller.signal.aborted) {
          console.error('Failed to poll query enrichment', error);
        }
      } finally {
        polling = false;
      }
    };

    const interval = window.setInterval(() => void poll(), 1000);
    void poll();
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [query, queryClient, result.data?.enrichment, result.data?.id]);

  return result;
}
