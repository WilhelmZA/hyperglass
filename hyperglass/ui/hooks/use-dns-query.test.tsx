import { afterEach, beforeEach, expect, describe, it, vi } from 'vitest';
import '@testing-library/jest-dom';
import { renderHook } from '@testing-library/react-hooks';
import { QueryClientProvider, QueryClient } from '@tanstack/react-query';
import { HyperglassContext } from '~/context';
import { useDNSQuery } from './use-dns-query';

import type { Config } from '~/types';

const fetchMock = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
  const requestUrl = new URL(String(input));
  const address = requestUrl.searchParams.get('type') === 'A' ? '1.1.1.1' : '2606:4700:4700::1111';
  return {
    json: async () => ({ Answer: [{ data: address }] }),
  } as Response;
});

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  fetchMock.mockClear();
});

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, cacheTime: Infinity } },
});

const CloudflareWrapper = (props: React.PropsWithChildren<Dict<JSX.Element>>) => {
  const config = {
    cache: { timeout: 120 },

    web: { dnsProvider: { url: 'https://cloudflare-dns.com/dns-query' } },
  } as Config;
  return (
    <QueryClientProvider client={queryClient}>
      <HyperglassContext.Provider value={config} {...props} />
    </QueryClientProvider>
  );
};

const GoogleWrapper = (props: React.PropsWithChildren<Dict<JSX.Element>>) => {
  const config = {
    cache: { timeout: 120 },
    web: { dnsProvider: { url: 'https://dns.google/resolve' } },
  } as Config;
  return (
    <QueryClientProvider client={queryClient}>
      <HyperglassContext.Provider value={config} {...props} />
    </QueryClientProvider>
  );
};

describe('useDNSQuery Cloudflare', () => {
  it('queries the configured Cloudflare provider for IPv4', async () => {
    const { result, waitFor } = renderHook(() => useDNSQuery('one.one.one.one', 4), {
      wrapper: CloudflareWrapper,
    });

    await waitFor(() => result.current.isSuccess, { timeout: 5_000 });
    expect(result.current.data?.Answer.map(a => a.data)).toContain('1.1.1.1');
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('https://cloudflare-dns.com/dns-query?name=one.one.one.one&type=A'),
      expect.objectContaining({ headers: { accept: 'application/dns-json' } }),
    );
  });

  it('queries the configured Cloudflare provider for IPv6', async () => {
    const { result, waitFor } = renderHook(() => useDNSQuery('one.one.one.one', 6), {
      wrapper: CloudflareWrapper,
    });
    await waitFor(() => result.current.isSuccess, { timeout: 5_000 });
    expect(result.current.data?.Answer.map(a => a.data)).toContain('2606:4700:4700::1111');
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining(
        'https://cloudflare-dns.com/dns-query?name=one.one.one.one&type=AAAA',
      ),
      expect.objectContaining({ headers: { accept: 'application/dns-json' } }),
    );
  });
});

describe('useDNSQuery Google', () => {
  it('queries the configured Google provider for IPv4', async () => {
    const { result, waitFor } = renderHook(() => useDNSQuery('one.one.one.one', 4), {
      wrapper: GoogleWrapper,
    });
    await waitFor(() => result.current.isSuccess, { timeout: 5_000 });
    expect(result.current.data?.Answer.map(a => a.data)).toContain('1.1.1.1');
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('https://dns.google/resolve?name=one.one.one.one&type=A'),
      expect.objectContaining({ headers: { accept: 'application/dns-json' } }),
    );
  });

  it('queries the configured Google provider for IPv6', async () => {
    const { result, waitFor } = renderHook(() => useDNSQuery('one.one.one.one', 6), {
      wrapper: GoogleWrapper,
    });
    await waitFor(() => result.current.isSuccess, { timeout: 5_000 });
    expect(result.current.data?.Answer.map(a => a.data)).toContain('2606:4700:4700::1111');
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('https://dns.google/resolve?name=one.one.one.one&type=AAAA'),
      expect.objectContaining({ headers: { accept: 'application/dns-json' } }),
    );
  });
});
