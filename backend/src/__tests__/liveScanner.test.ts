import request from 'supertest';
import app from '../index';
import {
  parseHtmlContent,
  analyzeSecurityHeaders,
  isLocalOrPrivateTarget,
  executeLiveScan,
  detectWaf,
} from '../services/liveScannerService';
import axios from 'axios';

// Mock axios for predictable test runs
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock mongoose
jest.mock('mongoose', () => {
  const actualMongoose = jest.requireActual('mongoose');
  return {
    ...actualMongoose,
    connect: jest.fn().mockResolvedValue(true),
  };
});

describe('Live Scanner Service - Unit Tests', () => {
  describe('isLocalOrPrivateTarget', () => {
    it('should correctly identify localhost and loopback addresses', () => {
      expect(isLocalOrPrivateTarget('localhost')).toBe(true);
      expect(isLocalOrPrivateTarget('127.0.0.1')).toBe(true);
      expect(isLocalOrPrivateTarget('::1')).toBe(true);
      expect(isLocalOrPrivateTarget('app.localhost')).toBe(true);
      expect(isLocalOrPrivateTarget('sandbox.test')).toBe(true);
    });

    it('should identify private RFC 1918 IP addresses', () => {
      expect(isLocalOrPrivateTarget('10.0.0.5')).toBe(true);
      expect(isLocalOrPrivateTarget('192.168.1.100')).toBe(true);
      expect(isLocalOrPrivateTarget('172.20.10.2')).toBe(true);
    });

    it('should return false for public internet hostnames', () => {
      expect(isLocalOrPrivateTarget('google.com')).toBe(false);
      expect(isLocalOrPrivateTarget('8.8.8.8')).toBe(false);
    });
  });

  describe('parseHtmlContent', () => {
    const sampleHtml = `
      <!DOCTYPE html>
      <html>
      <head><title>Test App</title></head>
      <body>
        <form action="/login" method="POST">
          <input type="text" name="username" value="admin" />
          <input type="password" name="password" />
          <button type="submit">Sign In</button>
        </form>

        <form action="/upload" method="POST" enctype="multipart/form-data">
          <input type="file" name="avatar" />
          <input type="text" name="desc" />
        </form>

        <form action="/search" method="GET">
          <input type="text" name="query" value="security" />
        </form>

        <a href="/products?category=electronics&page=2">Electronics</a>
        <a href="/user/profile?id=42">Profile</a>

        <script>
          function loadUserData() {
            fetch('/api/v1/users?active=true');
            axios.get('/api/admin/metrics');
            const url = "/auth/status";
          }
        </script>
      </body>
      </html>
    `;

    it('should extract forms and their inputs correctly', () => {
      const parsed = parseHtmlContent(sampleHtml, 'http://localhost:3000/app');
      expect(parsed.forms.length).toBe(3);

      const loginForm = parsed.forms.find((f) => f.action.includes('/login'));
      expect(loginForm).toBeDefined();
      expect(loginForm?.method).toBe('POST');
      expect(loginForm?.isFileUpload).toBe(false);
      expect(loginForm?.inputs.some((i) => i.name === 'username')).toBe(true);
      expect(loginForm?.inputs.some((i) => i.name === 'password')).toBe(true);
    });

    it('should flag multipart/form-data as file upload forms', () => {
      const parsed = parseHtmlContent(sampleHtml, 'http://localhost:3000/app');
      const uploadForm = parsed.forms.find((f) => f.action.includes('/upload'));
      expect(uploadForm).toBeDefined();
      expect(uploadForm?.isFileUpload).toBe(true);
    });

    it('should extract query parameters from links', () => {
      const parsed = parseHtmlContent(sampleHtml, 'http://localhost:3000/app');
      expect(parsed.linksWithParams.some((l) => l.param === 'category')).toBe(true);
      expect(parsed.linksWithParams.some((l) => l.param === 'id' && l.value === '42')).toBe(true);
    });

    it('should discover API endpoints referenced in inline scripts', () => {
      const parsed = parseHtmlContent(sampleHtml, 'http://localhost:3000/app');
      expect(parsed.scriptApiEndpoints).toContain('/api/v1/users?active=true');
      expect(parsed.scriptApiEndpoints).toContain('/api/admin/metrics');
      expect(parsed.scriptApiEndpoints).toContain('/auth/status');
    });
  });

  describe('analyzeSecurityHeaders', () => {
    it('should evaluate security headers and detect missing headers', () => {
      const headers = {
        'content-type': 'text/html; charset=utf-8',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'SAMEORIGIN',
      };

      const audit = analyzeSecurityHeaders(headers, false);
      expect(audit['X-Content-Type-Options'].status).toBe('pass');
      expect(audit['X-Frame-Options'].status).toBe('pass');
      expect(audit['Content-Security-Policy'].status).toBe('fail');
      expect(audit['Strict-Transport-Security'].status).toBe('warn');
    });

    it('should detect unsafe CSP directives', () => {
      const headers = {
        'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline';",
      };
      const audit = analyzeSecurityHeaders(headers, true);
      expect(audit['Content-Security-Policy'].status).toBe('warn');
    });
  });

  describe('detectWaf', () => {
    it('should detect Cloudflare WAF via headers and cookies', () => {
      const headers = {
        'server': 'cloudflare',
        'cf-ray': '8901234567-SJC',
        'set-cookie': '__cf_bm=xyz123',
      };
      const result = detectWaf(headers, '<html><body>Cloudflare protected</body></html>', 200);
      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('Cloudflare');
    });

    it('should detect AWS WAF via request headers', () => {
      const headers = {
        'x-amzn-requestid': 'abc-123-def',
        'server': 'awswaf',
      };
      const result = detectWaf(headers, '', 200);
      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('AWS WAF');
    });

    it('should detect Imperva / Incapsula via x-iinfo', () => {
      const headers = {
        'x-iinfo': '14-123456-123456 NNNN 0 0 0 - - - -',
      };
      const result = detectWaf(headers, '', 200);
      expect(result.detected).toBe(true);
      expect(result.vendor).toBe('Imperva / Incapsula');
    });

    it('should return detected: false for standard unprotected websites', () => {
      const headers = {
        'server': 'Apache/2.4.41 (Ubuntu)',
        'content-type': 'text/html',
      };
      const result = detectWaf(headers, '<html><body>Normal website</body></html>', 200);
      expect(result.detected).toBe(false);
      expect(result.vendor).toBeNull();
    });
  });
});

describe('Live Scanner API Endpoint (POST /api/scan)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should reject requests without target URL', async () => {
    const res = await request(app).post('/api/scan').send({ authorized: true });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Target URL is required/i);
  });

  it('should reject scans when authorized permission flag is false', async () => {
    const res = await request(app).post('/api/scan').send({
      url: 'http://localhost:3000/test',
      authorized: false,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Authorization confirmation required/i);
  });

  it('should successfully run a passive scan and return structured results', async () => {
    const mockAxiosInstance = {
      get: jest.fn().mockResolvedValue({
        status: 200,
        headers: {
          'server': 'nginx/1.18.0',
          'content-type': 'text/html',
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
        },
        data: `
          <html>
            <body>
              <form action="/search" method="GET">
                <input name="q" value="test" />
              </form>
              <a href="/items?id=123">Item</a>
              <script>
                fetch('/api/v1/health');
              </script>
            </body>
          </html>
        `,
      }),
      post: jest.fn(),
    };

    mockedAxios.create.mockReturnValue(mockAxiosInstance as unknown as ReturnType<typeof axios.create>);

    const res = await request(app).post('/api/scan').send({
      url: 'http://localhost:3000/search?q=test',
      authorized: true,
      scanMode: 'passive',
    });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('targetUrl', 'http://localhost:3000/search?q=test');
    expect(res.body).toHaveProperty('scanMode', 'passive');
    expect(res.body).toHaveProperty('headers');
    expect(res.body.headers).toHaveProperty('X-Frame-Options');
    expect(res.body.headers['X-Frame-Options'].status).toBe('pass');
    expect(res.body).toHaveProperty('discoveredEndpoints');
    expect(res.body.discoveredEndpoints.forms.length).toBeGreaterThan(0);
    expect(res.body.discoveredEndpoints.scriptApiEndpoints).toContain('/api/v1/health');
    expect(res.body).toHaveProperty('summary');
    expect(res.body.summary).toHaveProperty('riskScore');
    expect(res.body.summary).toHaveProperty('headersCompliance');
  });

  it('should also be accessible via /api/scanner/scan', async () => {
    const mockAxiosInstance = {
      get: jest.fn().mockResolvedValue({
        status: 200,
        headers: {},
        data: '<html><body>Hello World</body></html>',
      }),
      post: jest.fn(),
    };

    mockedAxios.create.mockReturnValue(mockAxiosInstance as unknown as ReturnType<typeof axios.create>);

    const res = await request(app).post('/api/scanner/scan').send({
      url: 'http://localhost:3000',
      authorized: true,
    });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('targetUrl');
    expect(res.body).toHaveProperty('scanMode', 'passive');
  });
});
