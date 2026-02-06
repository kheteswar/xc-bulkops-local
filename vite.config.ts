import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import type { IncomingMessage, ServerResponse } from 'http';
import https from 'https';

/**
 * Make HTTPS request to F5 XC API
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
 * Handle proxy requests to F5 XC API
 */
async function handleProxyRequest(req: IncomingMessage, res: ServerResponse) {
  // Read request body
  let body = '';
  for await (const chunk of req) {
    body += chunk;
  }

  try {
    const { tenant, token, endpoint, method = 'GET', body: requestBody } = JSON.parse(body);

    if (!tenant || !token || !endpoint) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing required fields: tenant, token, endpoint' }));
      return;
    }

    const hostname = `${tenant}.console.ves.volterra.io`;
    console.log(`[F5 XC Proxy] ${method} https://${hostname}${endpoint}`);

    const postData = requestBody ? JSON.stringify(requestBody) : undefined;
    
    const options: https.RequestOptions = {
      hostname,
      port: 443,
      path: endpoint,
      method: method.toUpperCase(),
      headers: {
        'Authorization': `APIToken ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(postData && { 'Content-Length': Buffer.byteLength(postData) }),
      },
    };

    const response = await makeF5XCRequest(options, postData);
    
    let responseData;
    try {
      responseData = JSON.parse(response.body);
    } catch {
      responseData = { message: response.body };
    }

    console.log(`[F5 XC Proxy] Response: ${response.statusCode}`);

    res.writeHead(response.statusCode >= 400 ? response.statusCode : 200, {
      'Content-Type': 'application/json',
    });

    if (response.statusCode >= 400) {
      res.end(JSON.stringify({
        error: responseData.message || responseData.error || `API Error: ${response.statusCode}`,
        details: responseData,
      }));
    } else {
      res.end(JSON.stringify(responseData));
    }

  } catch (error) {
    console.error('[F5 XC Proxy] Error:', error);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      error: error instanceof Error ? error.message : 'Proxy request failed' 
    }));
  }
}

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'f5xc-proxy',
      configureServer(server) {
        // Handle /api/proxy requests
        server.middlewares.use('/api/proxy', (req, res, next) => {
          if (req.method === 'POST') {
            handleProxyRequest(req, res);
          } else if (req.method === 'OPTIONS') {
            // Handle CORS preflight
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

        // Health check endpoint
        server.middlewares.use('/api/health', (req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
        });

        console.log('\n  🔌 F5 XC API Proxy enabled at /api/proxy\n');
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
