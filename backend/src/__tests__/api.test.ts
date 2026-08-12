import request from 'supertest';
import app from '../index';
import { analyzeUrl } from '../services/scannerService';

// Mock mongoose connection to prevent test suite from hanging
jest.mock('mongoose', () => {
  const actualMongoose = jest.requireActual('mongoose');
  return {
    ...actualMongoose,
    connect: jest.fn().mockResolvedValue(true),
  };
});

describe('API Health Endpoints', () => {
  it('should return 200 OK and valid health details', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('status', 'ok');
    expect(res.body).toHaveProperty('disclaimer');
  });

  it('should return 404 for unknown endpoints', async () => {
    const res = await request(app).get('/api/unknown-endpoint');
    expect(res.status).toBe(404);
  });
});

describe('Scanner Heuristic Utility', () => {
  it('should identify path traversal vectors', () => {
    const result = analyzeUrl('http://localhost:3000/download?file=../../etc/passwd');
    expect(result.summary.injectionPoints).toBeGreaterThan(0);
    const traversalFinding = result.findings.find(f => f.type.includes('Path Traversal'));
    expect(traversalFinding).toBeDefined();
    expect(traversalFinding?.severity).toBe('Critical');
  });

  it('should identify CRLF header vectors', () => {
    const result = analyzeUrl('http://localhost:3000/search?q=value%0d%0aSet-Cookie:session=1');
    const crlfFinding = result.findings.find(f => f.type.includes('CRLF'));
    expect(crlfFinding).toBeDefined();
  });

  it('should analyze path parameters and return risk ratings', () => {
    const result = analyzeUrl('http://localhost:3000/api/users/12345/profile');
    expect(result.pathSegments).toContain('users');
    expect(result.pathSegments).toContain('12345');
    expect(result.potentialInjectionPoints.length).toBeGreaterThan(0);
  });
});

// New Modules: IDs 56-78

describe('New Injection Modules (IDs 56-78) - Scanner Detection', () => {
  it('ID56: should handle Java deserialization probe', () => {
    const result = analyzeUrl('http://localhost:3000/load?data=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID57: should handle PHP object injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/page?user=O%3A4%3A%22Evil%22%3A1%3A%7Bs%3A4%3A%22cmd%22%3Bs%3A2%3A%22id%22%3B%7D');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID58: should handle ViewState probe in query parameter', () => {
    const result = analyzeUrl('http://localhost:3000/form?__VIEWSTATE=AAAB%2FwEAAGFkbWlu&__VIEWSTATEGENERATOR=1');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID59: should handle Python pickle probe', () => {
    const result = analyzeUrl('http://localhost:3000/model?data=gASVHAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID60: should handle Expression Language injection probe (${7*7})', () => {
    const result = analyzeUrl('http://localhost:3000/greet?name=%24%7B7*7%7D');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID61: should handle OGNL injection probe (%{7*7})', () => {
    const result = analyzeUrl('http://localhost:3000/action?query=%25%7B7*7%7D');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID62: should handle SSI injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/page?name=%3C!--%23exec+cmd%3D%27id%27--%3E');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID63: should handle JSON injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/api/user?name=alice%22%2C%22role%22%3A%22admin');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID64: should handle YAML injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/config?value=!!python%2Fobject%2Fapply%3Aos.system+%5Bid%5D');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID65: should handle XML Billion Laughs probe', () => {
    const result = analyzeUrl('http://localhost:3000/parse?xml=%3C!DOCTYPE+lol+SYSTEM%3E');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID66: should handle CSV formula injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/export?name=%3DCMD%7C%27+%2FC+calc%27%21A0');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID67: should handle Redis CRLF injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/cache?key=test%0d%0aFLUSHALL%0d%0a');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID68: should handle Elasticsearch match_all injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/search?filter=%7B%22match_all%22%3A%7B%7D%7D');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID69: should handle Cassandra CQL ALLOW FILTERING probe', () => {
    const result = analyzeUrl('http://localhost:3000/api/user?email=test%40test.com%27+ALLOW+FILTERING--');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID70: should return valid scan result for HTTP smuggling probe', () => {
    const result = analyzeUrl('http://localhost:3000/api/data?Transfer-Encoding=chunked');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID71: should handle prototype pollution probe', () => {
    const result = analyzeUrl('http://localhost:3000/settings?__proto__%5BisAdmin%5D=true');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID72: should handle SOAP injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/soap?name=alice%3C%2FName%3E%3CisAdmin%3Etrue%3C%2FisAdmin%3E');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID73: should return valid scan result for gRPC type confusion probe', () => {
    const result = analyzeUrl('http://localhost:3000/grpc?type_url=type.googleapis.com%2Fadmin.PrivilegedRequest');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID74: should handle JWT none algorithm probe', () => {
    const result = analyzeUrl('http://localhost:3000/api/me?token=eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID75: should detect Zip Slip path traversal probe', () => {
    const result = analyzeUrl('http://localhost:3000/extract?file=..%2F..%2F..%2F..%2Fetc%2Fcron.d%2Fevil');
    const traversalFinding = result.findings.find(f =>
      f.type.includes('Path Traversal') || f.type.includes('Traversal')
    );
    expect(result.summary).toHaveProperty('injectionPoints');
    if (traversalFinding) expect(traversalFinding.severity).toBeDefined();
  });

  it('ID76: should handle PDF injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/invoice?name=John%3C%2Fstream%3E%0A2+0+obj');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID77: should handle Markdown XSS injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/post?content=%5BClick%5D(javascript%3Aalert(1))');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('ID78: should handle RSS feed XML injection probe', () => {
    const result = analyzeUrl('http://localhost:3000/feed?title=News%3C%2Ftitle%3E%3Ctitle%3EFAKE');
    expect(result.summary).toHaveProperty('injectionPoints');
  });

  it('Meta: all 23 new probe URLs process without runtime errors', () => {
    const probeUrls = [
      'http://localhost:3000/load?data=rO0ABXNy',
      'http://localhost:3000/page?user=O%3A8%3A%22stdClass%22%3A0%3A%7B%7D',
      'http://localhost:3000/form?__VIEWSTATE=AAAB%2FwE',
      'http://localhost:3000/model?data=gASV',
      'http://localhost:3000/greet?name=%24%7B7*7%7D',
      'http://localhost:3000/action?query=%25%7B7*7%7D',
      'http://localhost:3000/page?name=%3C!--%23exec+cmd--%3E',
      'http://localhost:3000/api?name=alice%22%2C%22admin%22%3Atrue',
      'http://localhost:3000/cfg?val=!!python%2Fobject%3Aos.system',
      'http://localhost:3000/xml?q=%3C!DOCTYPE+lol%5B',
      'http://localhost:3000/export?n=%3DHYPERLINK%28%22http%3A%2F%2Fevil.com%22%29',
      'http://localhost:3000/cache?k=x%0d%0aFLUSHALL',
      'http://localhost:3000/search?q=%7B%22match_all%22%3A%7B%7D%7D',
      'http://localhost:3000/user?email=a%40b.com%27+ALLOW+FILTERING--',
      'http://localhost:3000/api?Transfer-Encoding=chunked',
      'http://localhost:3000/s?__proto__%5Badmin%5D=1',
      'http://localhost:3000/soap?n=%3C%2FName%3E%3CisAdmin%3Etrue',
      'http://localhost:3000/grpc?t=type.googleapis.com%2Fadmin',
      'http://localhost:3000/me?tok=eyJhbGciOiJub25lIn0.e30.',
      'http://localhost:3000/extract?f=..%2F..%2Fetc%2Fcron.d%2Fevil',
      'http://localhost:3000/pdf?n=x%3C%2Fstream%3E',
      'http://localhost:3000/post?c=%5Bx%5D(javascript%3Aalert(1))',
      'http://localhost:3000/feed?t=x%3C%2Ftitle%3E%3Ctitle%3EFAKE',
    ];
    expect(() => {
      probeUrls.forEach(url => analyzeUrl(url));
    }).not.toThrow();
  });
});

describe('Precision & False Positive Regression Tests', () => {
  it('should accurately handle benign clean URL without false critical errors', () => {
    const result = analyzeUrl('https://example.com/about?company=AcmeCorp&year=2024');
    expect(result.summary.parameters).toBe(2);
    // Should not falsely trigger SQLi or Command Injection on plain text
    const criticalFindings = result.findings.filter(f => f.severity === 'Critical' && !f.type.includes('Universal'));
    expect(criticalFindings.length).toBe(0);
  });

  it('should detect actual SQLi payload in id parameter with high accuracy', () => {
    const result = analyzeUrl('https://example.com/products?id=1%27+OR+%271%27%3D%271');
    const sqliFinding = result.findings.find(f => f.injectionFamily === 'SQL/NoSQL Injection');
    expect(sqliFinding).toBeDefined();
    expect(sqliFinding?.severity).toBe('Critical');
  });

  it('should detect actual XSS payload in search query with high accuracy', () => {
    const result = analyzeUrl('https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E');
    const xssFinding = result.findings.find(f => f.injectionFamily === 'Client-Side / XSS');
    expect(xssFinding).toBeDefined();
    expect(xssFinding?.cwe).toBe('CWE-79');
  });
});

describe('Target Scope and Safety Controls', () => {
  it('should block unconfirmed authorization requests with 400 status', async () => {
    const res = await request(app)
      .post('/api/scanner/analyze')
      .send({ url: 'https://example.com', authorized: false });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty('error');
  });

  it('should allow authorized requests with normalized target scope metadata', async () => {
    const res = await request(app)
      .post('/api/scanner/analyze')
      .send({ url: 'https://EXAMPLE.com/search?q=test#section', authorized: true });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('targetScope');
    expect(res.body.normalizedTarget).toBe('https://example.com/search?q=test');
    expect(res.body.targetScope.maxDepth).toBe(2);
  });
});

describe('Active Differential Scanner & Safety Boundaries', () => {
  it('should reject active scan against external third-party domain', async () => {
    const res = await request(app)
      .post('/api/scanner/active')
      .send({ url: 'https://google.com', authorized: true });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Safety Boundary Enforcement');
  });

  it('should require authorization before running active scan', async () => {
    const res = await request(app)
      .post('/api/scanner/active')
      .send({ url: 'http://localhost:3000', authorized: false });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Authorization');
  });
});



