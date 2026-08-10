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
