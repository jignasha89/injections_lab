const http = require('http');
const url = require('url');

const PORT = 3001;

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const query = parsedUrl.query;

  // Intentionally omitting Content-Security-Policy and X-Frame-Options for educational testing
  res.setHeader('Server', 'InjectionLab-MockTarget/1.0');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Collect request body for POST
  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
  });

  req.on('end', () => {
    let postParams = {};
    if (body) {
      try {
        if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
          postParams = JSON.parse(body);
        } else {
          const qs = require('querystring');
          postParams = qs.parse(body);
        }
      } catch (e) {
        postParams = {};
      }
    }

    // 1. Home / Landing Page
    if (pathname === '/' || pathname === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Mock Educational Target App</title>
  <style>
    body { font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
    .card { background: #1e293b; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; border: 1px solid #334155; }
    input, button { padding: 0.5rem; border-radius: 4px; border: 1px solid #475569; background: #0f172a; color: white; }
    button { background: #0ea5e9; cursor: pointer; font-weight: bold; border: none; }
    a { color: #38bdf8; text-decoration: none; margin-right: 1rem; }
  </style>
</head>
<body>
  <h1>🛡️ Mock Vulnerable Target (Port 3001)</h1>
  <p>Local sandbox target for testing InjectionLab scanner (forms, headers, scripts, differential probes).</p>

  <div class="card">
    <h3>🔍 Search Portal (GET Form)</h3>
    <form action="/search" method="GET">
      <input type="text" name="q" value="${query.q || 'security'}" placeholder="Search products..." />
      <button type="submit">Search</button>
    </form>
  </div>

  <div class="card">
    <h3>🔑 User Authentication (POST Form)</h3>
    <form action="/login" method="POST">
      <input type="text" name="username" placeholder="Username" value="admin" />
      <input type="password" name="password" placeholder="Password" />
      <button type="submit">Sign In</button>
    </form>
  </div>

  <div class="card">
    <h3>💬 Customer Feedback (POST Form)</h3>
    <form action="/feedback" method="POST">
      <input type="text" name="name" placeholder="Your Name" />
      <input type="text" name="comment" placeholder="Feedback / Template comment" />
      <button type="submit">Send Feedback</button>
    </form>
  </div>

  <div class="card">
    <h3>📦 Catalog Links</h3>
    <a href="/products?category=electronics&id=101">Electronics (#101)</a>
    <a href="/products?category=books&id=202">Books (#202)</a>
    <a href="/profile?userId=42&view=summary">User Profile (ID 42)</a>
  </div>

  <script>
    // Inline script with simulated endpoints for discovery
    function initClientApp() {
      fetch('/api/v1/user/status');
      fetch('/api/metrics');
      const authEndpoint = "/auth/check-session";
      console.log('Mock client initialized');
    }
    initClientApp();
  </script>
</body>
</html>
      `);
      return;
    }

    // 2. Search endpoint (Reflection / XSS demo)
    if (pathname === '/search') {
      const q = query.q || postParams.q || '';
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
        <html>
        <body>
          <h2>Search Results</h2>
          <p>Query: ${q}</p>
          <a href="/">Back</a>
        </body>
        </html>
      `);
      return;
    }

    // 3. Login endpoint (SQL Error Probe demo)
    if (pathname === '/login') {
      const user = postParams.username || query.username || '';
      const pass = postParams.password || query.password || '';

      // If user input contains single quote, simulate MySQL syntax error
      if (user.includes("'")) {
        res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`
          <html><body>
          <h1>Internal Server Error</h1>
          <p>Warning: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${user}' at line 1</p>
          </body></html>
        `);
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<html><body><p>Login attempt recorded for: ${user}</p></body></html>`);
      return;
    }

    // 4. Products endpoint (SQLi + Timing Demo)
    if (pathname === '/products') {
      const id = query.id || '1';

      if (id.includes("'") || id.includes("OR")) {
        res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<html><body><p>SQLException: Unclosed quotation mark after the character string near '${id}'.</p></body></html>`);
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', productId: id, name: 'Sample Item' }));
      return;
    }

    // 5. Feedback / Template endpoint (SSTI Demo)
    if (pathname === '/feedback') {
      const comment = postParams.comment || query.comment || '';

      // Simulate SSTI math calculation
      let rendered = comment;
      if (comment.includes('{{77*77}}')) {
        rendered = 'Computed Result: 5929';
      }

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<html><body><h2>Feedback Received</h2><p>${rendered}</p></body></html>`);
      return;
    }

    // 6. JSON API endpoints
    if (pathname === '/api/v1/user/status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ authenticated: true, role: 'student', active: true }));
      return;
    }

    if (pathname === '/api/metrics') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ uptime: process.uptime(), load: '0.05' }));
      return;
    }

    // 7. SPA / React-like client-rendered dynamic form route
    if (pathname === '/spa') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>SPA Client-Rendered Portal</title>
          <style>
            body { font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem; }
            .card { background: #1e293b; padding: 1.5rem; border-radius: 8px; border: 1px solid #334155; }
            input, button { padding: 0.5rem; border-radius: 4px; border: 1px solid #475569; background: #0f172a; color: white; margin-right: 0.5rem; }
            button { background: #0ea5e9; cursor: pointer; font-weight: bold; border: none; }
          </style>
        </head>
        <body>
          <h1>⚡ Single Page App (Client Rendered)</h1>
          <div id="root">
            <p id="loading">Loading interactive React components...</p>
          </div>
          <script>
            // Simulate client-side React / Vue DOM mounting after brief script execution
            setTimeout(() => {
              const root = document.getElementById('root');
              root.innerHTML = \`
                <div class="card">
                  <h3>📬 Dynamic Contact Form (Rendered via JavaScript)</h3>
                  <form id="spa-contact-form" action="/api/contact" method="POST">
                    <input type="text" name="email" placeholder="Your Email" value="student@injectionlab.local" />
                    <input type="text" name="message" placeholder="Message" value="Hello security auditor" />
                    <button type="submit">Submit Message</button>
                  </form>
                </div>
              \`;
            }, 100);
          </script>
        </body>
        </html>
      `);
      return;
    }

    if (pathname === '/api/contact') {
      const email = postParams.email || query.email || '';
      const message = postParams.message || query.message || '';

      // If single quote error probe is submitted
      if (email.includes("'")) {
        res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<html><body><p>Database Error: You have an error in your SQL syntax near '${email}'</p></body></html>`);
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'success', email, message }));
      return;
    }

    // 8. WAF Demo Endpoint (Simulates Cloudflare / Security Gateway)
    if (pathname === '/waf-demo') {
      res.setHeader('Server', 'cloudflare');
      res.setHeader('cf-ray', '8901234567abcdef-SJC');
      res.setHeader('cf-cache-status', 'DYNAMIC');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>WAF Protected Service</title></head>
        <body>
          <h1>🔒 Secure Banking Portal</h1>
          <p>Protected by Cloudflare Edge Security Engine.</p>
          <form action="/login" method="POST">
            <input type="text" name="user" placeholder="Username" />
            <input type="password" name="pin" placeholder="PIN" />
            <button type="submit">Access Account</button>
          </form>
        </body>
        </html>
      `);
      return;
    }

    // Default 404
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Mock Target Sandbox server is live and listening on http://localhost:${PORT}`);
  console.log(`   - Root: http://localhost:${PORT}`);
  console.log(`   - Search: http://localhost:${PORT}/search?q=test`);
  console.log(`   - Products: http://localhost:${PORT}/products?id=101`);
  console.log(`   - Login: POST http://localhost:${PORT}/login`);
  console.log(`   - Dynamic SPA: http://localhost:${PORT}/spa`);
  console.log(`   - WAF Protected: http://localhost:${PORT}/waf-demo`);
});
