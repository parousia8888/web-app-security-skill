import { lookup as dnsLookup } from 'node:dns/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { Transform, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const SUPPORTED_METHODS = new Set(['GET', 'HEAD']);
const EXPLICITLY_ALLOWED_PRIVATE_REASONS = new Set(['private', 'loopback', 'shared']);

export class SafeHttpError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'SafeHttpError';
    this.code = code;
  }
}

function ipv4Number(address) {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0;
}

function ipv4In(address, base, prefix) {
  const value = ipv4Number(address);
  const network = ipv4Number(base);
  if (value === null || network === null) return false;
  const block = 2 ** (32 - prefix);
  return Math.floor(value / block) === Math.floor(network / block);
}

function parseIpv6(address) {
  let value = address.toLowerCase().split('%')[0];
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(value);
  if (mapped) return { mappedIpv4: mapped[1] };
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    const ipv4 = ipv4Number(value.slice(lastColon + 1));
    if (ipv4 === null) return null;
    value = `${value.slice(0, lastColon)}:${(ipv4 >>> 16).toString(16)}:${(ipv4 & 0xffff).toString(16)}`;
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const words = [...left, ...Array(missing).fill('0'), ...right].map((word) => Number.parseInt(word || '0', 16));
  if (words.length !== 8 || words.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)) return null;
  if (words.slice(0, 5).every((word) => word === 0) && words[5] === 0xffff) {
    return { mappedIpv4: `${words[6] >>> 8}.${words[6] & 0xff}.${words[7] >>> 8}.${words[7] & 0xff}` };
  }
  return { words };
}

export function addressPolicy(address) {
  const family = isIP(address);
  if (family === 4) {
    const blocked = [
      ['0.0.0.0', 8, 'unspecified'], ['10.0.0.0', 8, 'private'],
      ['100.64.0.0', 10, 'shared'], ['127.0.0.0', 8, 'loopback'],
      ['169.254.0.0', 16, 'link_local'], ['172.16.0.0', 12, 'private'],
      ['192.0.0.0', 24, 'reserved'], ['192.0.2.0', 24, 'documentation'],
      ['192.88.99.0', 24, 'reserved'], ['192.168.0.0', 16, 'private'],
      ['198.18.0.0', 15, 'benchmark'], ['198.51.100.0', 24, 'documentation'],
      ['203.0.113.0', 24, 'documentation'], ['224.0.0.0', 4, 'multicast'],
      ['240.0.0.0', 4, 'reserved'],
    ];
    const match = blocked.find(([base, prefix]) => ipv4In(address, base, prefix));
    return { family, allowed: !match, reason: match?.[2] || null };
  }
  if (family === 6) {
    const parsed = parseIpv6(address);
    if (!parsed) return { family, allowed: false, reason: 'invalid' };
    if (parsed.mappedIpv4) {
      const policy = addressPolicy(parsed.mappedIpv4);
      return { ...policy, family: 6, reason: policy.reason ? `ipv4_mapped_${policy.reason}` : null };
    }
    const [first, second] = parsed.words;
    let reason = null;
    if (parsed.words.every((word) => word === 0)) reason = 'unspecified';
    else if (parsed.words.slice(0, 7).every((word) => word === 0) && parsed.words[7] === 1) reason = 'loopback';
    else if (parsed.words.slice(0, 6).every((word) => word === 0)) reason = 'reserved';
    else if ((first & 0xfe00) === 0xfc00) reason = 'private';
    else if ((first & 0xffc0) === 0xfe80) reason = 'link_local';
    else if ((first & 0xffc0) === 0xfec0) reason = 'reserved';
    else if (first === 0x2001 && second === 0x0db8) reason = 'documentation';
    else if ((first & 0xff00) === 0xff00) reason = 'multicast';
    return { family, allowed: !reason, reason };
  }
  return { family: 0, allowed: false, reason: 'not_an_ip_address' };
}

export function addressAllowed(address, allowPrivateNetwork = false) {
  const policy = addressPolicy(address);
  const reason = policy.reason?.replace(/^ipv4_mapped_/, '');
  return policy.allowed || (allowPrivateNetwork && EXPLICITLY_ALLOWED_PRIVATE_REASONS.has(reason));
}

function normalizedHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).map(([name, value]) => [
    name.toLowerCase(), Array.isArray(value) ? value.join(', ') : value === undefined ? '' : String(value),
  ]));
}

function decoderFor(value) {
  const encoding = String(value || '').trim().toLowerCase();
  if (!encoding || encoding === 'identity') return null;
  if (encoding === 'gzip' || encoding === 'x-gzip') return createGunzip();
  if (encoding === 'deflate') return createInflate();
  if (encoding === 'br') return createBrotliDecompress();
  throw new SafeHttpError('unsupported_content_encoding', `unsupported content encoding: ${encoding}`);
}

function validateUrl(value, allowedOrigin) {
  let url;
  try { url = value instanceof URL ? new URL(value.href) : new URL(value); } catch {
    throw new SafeHttpError('invalid_url', 'request URL is invalid');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new SafeHttpError('unsupported_protocol', `request URL uses unsupported protocol: ${url.protocol}`);
  }
  if (url.username || url.password) throw new SafeHttpError('url_credentials_forbidden', 'request URL must not contain credentials');
  if (url.origin !== allowedOrigin) {
    throw new SafeHttpError('cross_origin_request_blocked', `request origin ${url.origin} is outside ${allowedOrigin}`);
  }
  return url;
}

async function resolvePinned(url, { allowPrivateNetwork, lookup }) {
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const literalFamily = isIP(hostname);
  const records = literalFamily
    ? [{ address: hostname, family: literalFamily }]
    : await lookup(hostname, { all: true, verbatim: true });
  if (!Array.isArray(records) || !records.length) {
    throw new SafeHttpError('dns_no_addresses', `DNS returned no addresses for ${hostname}`);
  }
  const normalized = records.map((record) => ({
    address: record.address, family: Number(record.family) || isIP(record.address),
  }));
  if (normalized.some((record) => ![4, 6].includes(record.family))) {
    throw new SafeHttpError('dns_invalid_address', `DNS returned an invalid address for ${hostname}`);
  }
  const blocked = normalized.find((record) => !addressAllowed(record.address, allowPrivateNetwork));
  if (blocked) {
    const policy = addressPolicy(blocked.address);
    throw new SafeHttpError('private_network_blocked', `refusing ${policy.reason} address for ${hostname}`);
  }
  return normalized[0];
}

function performRequest(url, { method, headers, signal, pinned }) {
  const request = url.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const req = request(url, {
      method,
      headers,
      signal,
      lookup: (_hostname, options, callback) => options?.all
        ? callback(null, [pinned])
        : callback(null, pinned.address, pinned.family),
      ...(url.protocol === 'https:' ? { servername: url.hostname.replace(/^\[|\]$/g, '') } : {}),
    }, resolve);
    req.on('error', reject);
    req.end();
  });
}

async function readBody(response, { maxResponseBytes, reserveTotalBytes }) {
  const headers = normalizedHeaders(response.headers);
  const declared = Number(headers['content-length']);
  if (Number.isFinite(declared) && declared > maxResponseBytes) {
    response.destroy();
    throw new SafeHttpError('response_wire_limit_exceeded', `response exceeds ${maxResponseBytes} wire bytes`);
  }
  let wireBytes = 0;
  let decodedBytes = 0;
  const chunks = [];
  const wireLimit = new Transform({
    transform(chunk, _encoding, callback) {
      wireBytes += chunk.length;
      if (wireBytes > maxResponseBytes) {
        callback(new SafeHttpError('response_wire_limit_exceeded', `response exceeds ${maxResponseBytes} wire bytes`));
      } else callback(null, chunk);
    },
  });
  const collector = new Writable({
    write(chunk, _encoding, callback) {
      decodedBytes += chunk.length;
      try {
        if (decodedBytes > maxResponseBytes) {
          throw new SafeHttpError('response_decoded_limit_exceeded', `decoded response exceeds ${maxResponseBytes} bytes`);
        }
        reserveTotalBytes(chunk.length);
        chunks.push(Buffer.from(chunk));
        callback();
      } catch (error) {
        callback(error);
      }
    },
  });
  let decoder;
  try {
    decoder = decoderFor(headers['content-encoding']);
  } catch (error) {
    response.destroy();
    throw error;
  }
  if (decoder) await pipeline(response, wireLimit, decoder, collector);
  else await pipeline(response, wireLimit, collector);
  return { body: Buffer.concat(chunks, decodedBytes).toString('utf8'), wireBytes, decodedBytes };
}

export function createSafeHttpClient({
  origin,
  allowPrivateNetwork = false,
  timeoutMs = 15_000,
  maxResponseBytes = 4 * 1024 * 1024,
  maxTotalBytes = 32 * 1024 * 1024,
  maxRequests = 128,
  maxRedirects = 5,
  lookup = dnsLookup,
} = {}) {
  let originUrl;
  try { originUrl = new URL(origin); } catch { throw new Error('origin must be a valid URL'); }
  if (!['http:', 'https:'].includes(originUrl.protocol)) throw new Error('origin must use http:// or https://');
  if (originUrl.username || originUrl.password) throw new Error('origin must not contain credentials');
  const allowedOrigin = originUrl.origin;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) throw new Error('timeoutMs must be a positive integer');
  for (const [name, value] of [['maxResponseBytes', maxResponseBytes], ['maxTotalBytes', maxTotalBytes], ['maxRequests', maxRequests]]) {
    if (!Number.isInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  }
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0) throw new Error('maxRedirects must be a non-negative integer');

  const budget = { requests: 0, decodedBytes: 0 };
  const reserveRequest = () => {
    if (budget.requests >= maxRequests) {
      throw new SafeHttpError('request_budget_exceeded', `request budget exceeds ${maxRequests}`);
    }
    budget.requests += 1;
  };
  const reserveTotalBytes = (bytes) => {
    if (budget.decodedBytes + bytes > maxTotalBytes) {
      throw new SafeHttpError('total_body_limit_exceeded', `decoded response budget exceeds ${maxTotalBytes} bytes`);
    }
    budget.decodedBytes += bytes;
  };

  return {
    async request(value, { method = 'GET', headers = {}, redirect = 'manual' } = {}) {
      method = String(method).toUpperCase();
      if (!SUPPORTED_METHODS.has(method)) throw new SafeHttpError('method_not_allowed', `request method is not allowed: ${method}`);
      if (!['manual', 'follow'].includes(redirect)) throw new SafeHttpError('redirect_mode_invalid', `unsupported redirect mode: ${redirect}`);
      let url = validateUrl(value, allowedOrigin);
      const redirects = [];
      for (let hop = 0; hop <= maxRedirects; hop += 1) {
        const controller = new AbortController();
        let rejectTimeout;
        const deadline = new Promise((_resolve, reject) => { rejectTimeout = reject; });
        const timeout = setTimeout(() => {
          controller.abort();
          rejectTimeout(new SafeHttpError('request_timeout', `request exceeded ${timeoutMs} ms`));
        }, timeoutMs);
        let result;
        try {
          result = await Promise.race([
            (async () => {
              reserveRequest();
              const pinned = await resolvePinned(url, { allowPrivateNetwork, lookup });
              if (controller.signal.aborted) throw new SafeHttpError('request_timeout', `request exceeded ${timeoutMs} ms`);
              const response = await performRequest(url, { method, headers, signal: controller.signal, pinned });
              const responseHeaders = normalizedHeaders(response.headers);
              if (redirect === 'follow' && REDIRECT_STATUSES.has(response.statusCode)) {
                const location = responseHeaders.location;
                response.destroy();
                if (!location) throw new SafeHttpError('redirect_location_missing', 'redirect response has no Location header');
                if (hop === maxRedirects) throw new SafeHttpError('redirect_limit_exceeded', `redirect count exceeds ${maxRedirects}`);
                let next;
                try { next = validateUrl(new URL(location, url), allowedOrigin); } catch (error) {
                  if (error instanceof SafeHttpError) throw error;
                  throw new SafeHttpError('redirect_location_invalid', 'redirect response has an invalid Location header');
                }
                return { redirect: { next, status: response.statusCode } };
              }
              let body = '', wireBytes = 0, decodedBytes = 0;
              if (method === 'HEAD') response.resume();
              else ({ body, wireBytes, decodedBytes } = await readBody(response, { maxResponseBytes, reserveTotalBytes }));
              return { response: {
                url: value instanceof URL ? value.href : String(value),
                finalUrl: url.href,
                status: response.statusCode || 0,
                headers: responseHeaders,
                body,
                bytes: method === 'HEAD' ? Number(responseHeaders['content-length'] || 0) : decodedBytes,
                wireBytes,
                redirects,
              } };
            })(),
            deadline,
          ]);
          if (result.redirect) {
            redirects.push({ from: url.href, to: result.redirect.next.href, status: result.redirect.status });
            url = result.redirect.next;
          } else {
            return result.response;
          }
        } catch (error) {
          if (controller.signal.aborted || error.name === 'AbortError' || error.code === 'ABORT_ERR') {
            throw new SafeHttpError('request_timeout', `request exceeded ${timeoutMs} ms`);
          }
          throw error;
        } finally {
          clearTimeout(timeout);
        }
        if (result.redirect) continue;
      }
      throw new SafeHttpError('redirect_limit_exceeded', `redirect count exceeds ${maxRedirects}`);
    },
    snapshot() {
      return {
        allowedOrigin,
        allowPrivateNetwork,
        requests: budget.requests,
        maxRequests,
        decodedBytes: budget.decodedBytes,
        maxTotalBytes,
        maxResponseBytes,
        maxRedirects,
      };
    },
  };
}
