import { DetectionOutcome } from './scannerService';

/**
 * Interface representing a simulated or real HTTP response.
 */
export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  url: string;
}

/**
 * Configuration for the scanner's live tests
 */
export interface ScannerContext {
  baselineResponse?: HttpResponse;
}

/**
 * HTML Injection Detection Engine
 * Upgraded to use Baseline-First Detection and Context-Aware Analysis.
 */
export class HTMLInjectionDetector {
  
  /**
   * Evaluates if a given parameter reflects payload securely or insecurely
   * returns CONFIRMED if unsafe interpretation is guaranteed.
   */
  public analyzeReflection(
    paramName: string,
    payload: string,
    testResponse: HttpResponse,
    context?: ScannerContext
  ): { outcome: DetectionOutcome; evidence: string } {
    
    const body = testResponse.body;
    
    // 1. Is the payload even reflected?
    if (!body.includes(payload)) {
      return { outcome: 'NOT_TESTABLE', evidence: 'Payload was not reflected in the response.' };
    }

    // 2. Are we looking at an HTML content type? (If not HTML, it's not HTML Injection)
    const contentType = testResponse.headers['content-type'] || testResponse.headers['Content-Type'] || '';
    if (!contentType.toLowerCase().includes('text/html')) {
      return { outcome: 'INCONCLUSIVE', evidence: 'Payload reflected, but Content-Type is not text/html. Browser may not execute it as markup.' };
    }

    // 3. Baseline comparison (did the baseline also have this string? unlikely but good to check)
    if (context?.baselineResponse?.body.includes(payload)) {
      return { outcome: 'INCONCLUSIVE', evidence: 'Payload appears in test response, but was also present in the baseline (disturbance/static).' };
    }

    // 4. Check for proper escaping/sanitization
    // If the developer escaped the payload (e.g. < to &lt;), the literal payload string won't be found, 
    // it was already caught by condition 1.
    // However, what if they reflected it inside an attribute?
    
    // Regex to see if the payload is inside an HTML attribute value:
    // Capturing group 1 is the quote (' or ")
    const attributeContextRegex = new RegExp(`=(['"])(?:(?!\\1).)*?${this.escapeRegex(payload)}(?:(?!\\1).)*?\\1`, 'i');
    
    if (payload.includes('"') || payload.includes("'")) {
       // If it broke out of a double-quoted attribute
       const brokeOutDouble = new RegExp(`="[^"]*?${this.escapeRegex(payload)}`, 'i').test(body) && payload.includes('"');
       // If it broke out of a single-quoted attribute
       const brokeOutSingle = new RegExp(`='[^']*?${this.escapeRegex(payload)}`, 'i').test(body) && payload.includes("'");
       
       if (brokeOutDouble || brokeOutSingle) {
         return { outcome: 'PROBABLE', evidence: 'Payload reflected inside an attribute and appears to break the tag structure.' };
       }
    }

    if (attributeContextRegex.test(body)) {
      return { outcome: 'INCONCLUSIVE', evidence: 'Payload reflected safely inside an HTML attribute context. Tags are not interpreted as DOM nodes.' };
    }

    // Regex to see if it's inside a script tag
    const scriptContextRegex = new RegExp(`<script[^>]*>[\\s\\S]*?${this.escapeRegex(payload)}[\\s\\S]*?<\\/script>`, 'i');
    if (scriptContextRegex.test(body)) {
      return { outcome: 'INCONCLUSIVE', evidence: 'Payload reflected inside a <script> tag. This is XSS context, not pure HTML injection.' };
    }
    
    const styleContextRegex = new RegExp(`<style[^>]*>[\\s\\S]*?${this.escapeRegex(payload)}[\\s\\S]*?<\\/style>`, 'i');
    if (styleContextRegex.test(body)) {
      return { outcome: 'INCONCLUSIVE', evidence: 'Payload reflected inside a <style> tag.' };
    }

    // 5. If it is in standard HTML text context and literal payload is found (including < and >),
    // and the content type is HTML, the browser WILL interpret it.
    if (payload.includes('<') && payload.includes('>')) {
      return { 
        outcome: 'CONFIRMED', 
        evidence: `Payload '${payload}' was reflected completely unescaped in an active text/html context. The browser will render the injected DOM nodes.` 
      };
    }

    // 6. Fallback
    return { outcome: 'PROBABLE', evidence: 'Payload reflected in HTML text, but did not contain active markup characters to confirm DOM manipulation.' };
  }
  
  private escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}
