import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import type { IncomingMessage, ServerResponse } from 'http';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';

/**
 * Make HTTPS request to F5 XC API (and External APIs)
 * Used by the generic /api/proxy endpoint
 */
function makeF5XCRequest(options: https.RequestOptions, postData?: string): Promise<{
  statusCode: number;
  body: string;
}> {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 500,
          body: data,
        });
      });
    });
    
    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

/**
 * Handle generic proxy requests to F5 XC API & External APIs
 * Used by WAF Scanner, Security Auditor, Time Tracker, etc.
 */
async function handleProxyRequest(req: IncomingMessage, res: ServerResponse) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
  }

  try {
    const parsed = JSON.parse(body);
    const { tenant, token, endpoint, method = 'GET', body: requestBody, isExternal, targetUrl } = parsed;

    if (!token) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing token' }));
      return;
    }

    let hostname = '';
    let path = '';
    let authHeader = '';

    // NEW: Handle External APIs (like Time Tracker) differently
    if (isExternal && targetUrl) {
      const urlObj = new URL(targetUrl);
      hostname = urlObj.hostname;
      path = urlObj.pathname + urlObj.search;
      authHeader = `Bearer ${token}`; // External APIs typically use Bearer
    } else {
      // EXISTING: Standard F5 XC formatting
      if (!tenant || !endpoint) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing tenant or endpoint for F5 XC request' }));
        return;
      }
      hostname = `${tenant}.console.ves.volterra.io`;
      path = endpoint.startsWith('/api') ? endpoint : `/api${endpoint}`;
      authHeader = `APIToken ${token}`; // F5 XC requires APIToken prefix
    }

    const options: https.RequestOptions = {
      hostname: hostname,
      path: path,
      method: method,
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    };

    const response = await makeF5XCRequest(options, requestBody ? JSON.stringify(requestBody) : undefined);

    res.writeHead(response.statusCode, { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*' 
    });
    res.end(response.body);

  } catch (error: any) {
    console.error('Proxy error:', error);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: error.message }));
  }
}

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'f5xc-proxy',
      configureServer(server) {

        // -------------------------------------------------------------
        // 1. Sanity Checker Proxy (Specific Route)
        //    Handles "Live vs Spoof" requests with custom DNS logic
        // -------------------------------------------------------------
        server.middlewares.use('/api/proxy/request', (req, res, next) => {
          if (req.method !== 'POST') return next();

          let body = '';
          req.on('data', chunk => body += chunk);
          req.on('end', async () => {
            try {
              if (!body) throw new Error('Empty request body');
              const parsed = JSON.parse(body);
              
              // Destructure and validate
              const { url: targetUrl, method = 'GET', headers = {}, targetIp } = parsed;
              
              if (!targetUrl) throw new Error('Missing URL parameter');

              console.log(`[SanityProxy] ${method} ${targetUrl}`);
              console.log(`[SanityProxy] Raw targetIp:`, targetIp, `(type: ${typeof targetIp})`);

              const urlObj = new URL(targetUrl);
              const isHttps = urlObj.protocol === 'https:';
              
              // If we have a valid targetIp (not null, undefined, or empty), we need to spoof DNS
              const shouldSpoof = targetIp && typeof targetIp === 'string' && targetIp.trim().length > 0;
              
              if (shouldSpoof) {
                console.log(`[SanityProxy] Spoofing ${urlObj.hostname} -> ${targetIp}`);
                
                // For spoofed requests, we connect directly to the IP but use proper headers
                const spoofOptions: any = {
                  host: targetIp, // Connect to this IP
                  hostname: targetIp,
                  port: isHttps ? 443 : 80,
                  path: urlObj.pathname + urlObj.search,
                  method,
                  headers: {
                    ...headers,
                    // Ensure Host header is set to the original hostname
                    'Host': headers['Host'] || urlObj.hostname
                  },
                  rejectUnauthorized: false, // Allow self-signed certs
                  servername: urlObj.hostname, // SNI for HTTPS
                  timeout: 15000
                };

                const httpModule = isHttps ? https : http;
                const proxyReq = httpModule.request(spoofOptions, (proxyRes) => {
                  const chunks: Buffer[] = [];
                  let bodySize = 0;
                  const maxBodySize = 10 * 1024 * 1024; // 10MB limit

                  // Handle compression
                  let responseStream = proxyRes;
                  const encoding = proxyRes.headers['content-encoding'];
                  
                  if (encoding === 'gzip') {
                    responseStream = proxyRes.pipe(zlib.createGunzip());
                  } else if (encoding === 'deflate') {
                    responseStream = proxyRes.pipe(zlib.createInflate());
                  } else if (encoding === 'br') {
                    responseStream = proxyRes.pipe(zlib.createBrotliDecompress());
                  }

                  responseStream.on('data', (chunk: Buffer) => {
                    bodySize += chunk.length;
                    if (bodySize > maxBodySize) {
                      proxyReq.destroy();
                      console.error(`[SanityProxy] Response too large: ${bodySize} bytes`);
                      return;
                    }
                    chunks.push(chunk);
                  });

                  responseStream.on('end', () => {
                    const buffer = Buffer.concat(chunks);
                    const resBody = buffer.toString('utf-8');
                    console.log(`[SanityProxy] Spoofed response: ${proxyRes.statusCode} (${bodySize} bytes, encoding: ${encoding || 'none'})`);
                    const responseData = {
                      status: proxyRes.statusCode,
                      statusText: proxyRes.statusMessage,
                      headers: proxyRes.headers,
                      body: resBody,
                      connectedIp: targetIp // The IP we connected to
                    };
                    console.log(`[SanityProxy] Sending to frontend - connectedIp: ${responseData.connectedIp}`);
                    res.writeHead(200, { 
                      'Content-Type': 'application/json',
                      'Access-Control-Allow-Origin': '*'
                    });
                    res.end(JSON.stringify(responseData));
                  });

                  responseStream.on('error', (err: any) => {
                    console.error(`[SanityProxy] Decompression error:`, err.message);
                    if (!res.headersSent) {
                      res.writeHead(502, { 'Content-Type': 'application/json' });
                      res.end(JSON.stringify({ error: `Decompression Error: ${err.message}` }));
                    }
                  });
                });

                proxyReq.on('timeout', () => {
                  console.error(`[SanityProxy] Request timeout after 15s`);
                  proxyReq.destroy();
                  if (!res.headersSent) {
                    res.writeHead(504, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Request timeout after 15 seconds' }));
                  }
                });

                proxyReq.on('error', (err: any) => {
                  console.error(`[SanityProxy] Spoofed Request Error:`, err.message);
                  if (!res.headersSent) {
                    res.writeHead(502, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: `Spoofed Connection Failed: ${err.message}` }));
                  }
                });

                proxyReq.end();
              } else {
                // Live DNS request - use Google DNS resolver to bypass local /etc/hosts
                console.log(`[SanityProxy] Live DNS request to ${targetUrl}`);
                
                // Use Google DNS (8.8.8.8) for resolution
                const dnsResolver = new dns.promises.Resolver();
                dnsResolver.setServers(['8.8.8.8', '8.8.4.4']); // Google DNS servers
                
                // Resolve the hostname using Google DNS
                let resolvedIp: string;
                try {
                  const addresses = await dnsResolver.resolve4(urlObj.hostname);
                  resolvedIp = addresses[0];
                  console.log(`[SanityProxy] Google DNS resolved ${urlObj.hostname} -> ${resolvedIp}`);
                } catch (dnsError: any) {
                  console.error(`[SanityProxy] DNS resolution failed:`, dnsError.message);
                  throw new Error(`DNS resolution failed: ${dnsError.message}`);
                }
                
                // Now connect to the resolved IP
                const liveOptions: any = {
                  host: resolvedIp, // Connect to the Google DNS resolved IP
                  hostname: resolvedIp,
                  port: isHttps ? 443 : 80,
                  path: urlObj.pathname + urlObj.search,
                  method,
                  headers: {
                    ...headers,
                    'Host': urlObj.hostname // Keep original hostname in Host header
                  },
                  servername: urlObj.hostname, // SNI for HTTPS
                  rejectUnauthorized: false,
                  timeout: 15000
                };

                const httpModule = isHttps ? https : http;
                const proxyReq = httpModule.request(liveOptions, (proxyRes) => {
                  // Use the resolved IP as the connected IP
                  const connectedIp = resolvedIp;
                  
                  const chunks: Buffer[] = [];
                  let bodySize = 0;
                  const maxBodySize = 10 * 1024 * 1024; // 10MB limit

                  // Handle compression
                  let responseStream = proxyRes;
                  const encoding = proxyRes.headers['content-encoding'];
                  
                  if (encoding === 'gzip') {
                    responseStream = proxyRes.pipe(zlib.createGunzip());
                  } else if (encoding === 'deflate') {
                    responseStream = proxyRes.pipe(zlib.createInflate());
                  } else if (encoding === 'br') {
                    responseStream = proxyRes.pipe(zlib.createBrotliDecompress());
                  }

                  responseStream.on('data', (chunk: Buffer) => {
                    bodySize += chunk.length;
                    if (bodySize > maxBodySize) {
                      proxyReq.destroy();
                      console.error(`[SanityProxy] Response too large: ${bodySize} bytes`);
                      return;
                    }
                    chunks.push(chunk);
                  });

                  responseStream.on('end', () => {
                    const buffer = Buffer.concat(chunks);
                    const resBody = buffer.toString('utf-8');
                    console.log(`[SanityProxy] Live response: ${proxyRes.statusCode} (${bodySize} bytes, encoding: ${encoding || 'none'}, IP: ${connectedIp})`);
                    const responseData = {
                      status: proxyRes.statusCode,
                      statusText: proxyRes.statusMessage,
                      headers: proxyRes.headers,
                      body: resBody,
                      connectedIp: connectedIp // The actual IP we connected to
                    };
                    console.log(`[SanityProxy] Sending to frontend - connectedIp: ${responseData.connectedIp}`);
                    res.writeHead(200, { 
                      'Content-Type': 'application/json',
                      'Access-Control-Allow-Origin': '*'
                    });
                    res.end(JSON.stringify(responseData));
                  });

                  responseStream.on('error', (err: any) => {
                    console.error(`[SanityProxy] Decompression error:`, err.message);
                    if (!res.headersSent) {
                      res.writeHead(502, { 'Content-Type': 'application/json' });
                      res.end(JSON.stringify({ error: `Decompression Error: ${err.message}` }));
                    }
                  });
                });

                proxyReq.on('timeout', () => {
                  console.error(`[SanityProxy] Request timeout after 15s`);
                  proxyReq.destroy();
                  if (!res.headersSent) {
                    res.writeHead(504, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Request timeout after 15 seconds' }));
                  }
                });

                proxyReq.on('error', (err: any) => {
                  console.error(`[SanityProxy] Live Request Error:`, err.message);
                  if (!res.headersSent) {
                    res.writeHead(502, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: `Live Connection Failed: ${err.message}` }));
                  }
                });

                proxyReq.end();
              }
            } catch (e: any) {
              console.error(`[SanityProxy] Parse Error:`, e.message);
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: `Invalid Request: ${e.message}` }));
            }
          });
        });

        // -------------------------------------------------------------
        // 2. Generic F5 XC Proxy (General Route)
        //    Handles standard API calls for other tools
        // -------------------------------------------------------------
        server.middlewares.use('/api/proxy', (req, res, next) => {
          // IMPORTANT: If the URL matches the specific route above, do NOT process it here.
          // Note: req.originalUrl includes the full path, req.url is relative to mount point
          if (req.originalUrl && req.originalUrl.includes('/api/proxy/request')) {
            return next();
          }

          if (req.method === 'POST') {
            handleProxyRequest(req, res);
          } else if (req.method === 'OPTIONS') {
            res.writeHead(200, {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type',
            });
            res.end();
          } else {
            next();
          }
        });

        // -------------------------------------------------------------
        // 3. Health Check
        // -------------------------------------------------------------
        server.middlewares.use('/api/health', (req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
        });

        console.log('\n 🔌 F5 XC API Proxy enabled at /api/proxy');
        console.log(' 🔌 Sanity Checker Proxy enabled at /api/proxy/request\n');
      },
    },
  ],
  server: {
    port: 5173,
    open: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});