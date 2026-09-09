import { HTMLInjectionDetector, HttpResponse } from '../services/htmlInjectionDetector';

describe('HTML Injection Detector - Regression Matrix', () => {
  let detector: HTMLInjectionDetector;

  beforeEach(() => {
    detector = new HTMLInjectionDetector();
  });

  it('1. POSITIVE CASE - Vulnerable HTML Injection fixture (Unescaped)', () => {
    const payload = '<h1>Injected</h1>';
    const testResponse: HttpResponse = {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
      body: `<html><body>Welcome user: ${payload}</body></html>`,
      url: 'http://test.local/?name=<h1>Injected</h1>'
    };

    const result = detector.analyzeReflection('name', payload, testResponse);
    expect(result.outcome).toBe('CONFIRMED');
    expect(result.evidence).toContain('unescaped in an active text/html context');
  });

  it('2. NEGATIVE CASE - Securely escaped fixture', () => {
    const payload = '<h1>Injected</h1>';
    // Escaped reflection
    const testResponse: HttpResponse = {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
      body: `<html><body>Welcome user: &lt;h1&gt;Injected&lt;/h1&gt;</body></html>`,
      url: 'http://test.local/?name=<h1>Injected</h1>'
    };

    const result = detector.analyzeReflection('name', payload, testResponse);
    expect(result.outcome).toBe('NOT_TESTABLE'); // Payload is not literally reflected
  });

  it('3. NEGATIVE CASE - Sanitized fixture (Tags stripped)', () => {
    const payload = '<h1>Injected</h1>';
    // Sanitized reflection (tags stripped, just 'Injected' left)
    const testResponse: HttpResponse = {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
      body: `<html><body>Welcome user: Injected</body></html>`,
      url: 'http://test.local/?name=<h1>Injected</h1>'
    };

    const result = detector.analyzeReflection('name', payload, testResponse);
    expect(result.outcome).toBe('NOT_TESTABLE'); // Payload is not literally reflected
  });

  it('4. EDGE CASE - Inside HTML attribute securely (Unbroken)', () => {
    const payload = 'Injected';
    const testResponse: HttpResponse = {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
      body: `<html><body><input type="text" value="${payload}"></body></html>`,
      url: 'http://test.local/?name=Injected'
    };

    const result = detector.analyzeReflection('name', payload, testResponse);
    expect(result.outcome).toBe('INCONCLUSIVE');
    expect(result.evidence).toContain('safely inside an HTML attribute context');
  });

  it('4b. EDGE CASE - Inside HTML attribute breaking out', () => {
    const payload = '"><script>alert(1)</script>';
    const testResponse: HttpResponse = {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
      body: `<html><body><input type="text" value=""><script>alert(1)</script>"></body></html>`,
      url: 'http://test.local/?name="><script>alert(1)</script>'
    };

    const result = detector.analyzeReflection('name', payload, testResponse);
    expect(result.outcome).toBe('PROBABLE');
    expect(result.evidence).toContain('appears to break the tag structure');
  });

  it('5. NEGATIVE CASE - Reflection outside of text/html', () => {
    const payload = '<h1>Injected</h1>';
    const testResponse: HttpResponse = {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      body: `{"name": "<h1>Injected</h1>"}`,
      url: 'http://test.local/?name=<h1>Injected</h1>'
    };

    const result = detector.analyzeReflection('name', payload, testResponse);
    expect(result.outcome).toBe('INCONCLUSIVE');
    expect(result.evidence).toContain('Content-Type is not text/html');
  });

  it('6. NEGATIVE CASE - Baseline already had the payload', () => {
    const payload = '<h1>Injected</h1>';
    const testResponse: HttpResponse = {
      status: 200,
      headers: { 'Content-Type': 'text/html' },
      body: `<html><body>Welcome user: ${payload}</body></html>`,
      url: 'http://test.local/?name=<h1>Injected</h1>'
    };
    
    const baselineResponse: HttpResponse = {
      status: 200,
      headers: { 'Content-Type': 'text/html' },
      body: `<html><body>Welcome user: <h1>Injected</h1></body></html>`,
      url: 'http://test.local/'
    };

    const result = detector.analyzeReflection('name', payload, testResponse, { baselineResponse });
    expect(result.outcome).toBe('INCONCLUSIVE');
    expect(result.evidence).toContain('also present in the baseline');
  });
});
