import { captureFindingScreenshot, getBrowserExecutablePath } from '../services/screenshotService';

async function main() {
  console.log('Detected Browser Executable:', getBrowserExecutablePath());
  const finding = {
    type: 'SQL Injection',
    severity: 'critical',
    parameter: 'username',
    payload: "' OR 1=1 --",
  };
  const start = Date.now();
  const res = await captureFindingScreenshot(finding, 'http://testapp.local/login');
  console.log('Generated Screenshot prefix:', res.screenshot.substring(0, 40));
  console.log('Screenshot total length:', res.screenshot.length);
  console.log('Screenshot Caption:', res.screenshotCaption);
  console.log('Completed in:', Date.now() - start, 'ms');
}

main().catch(console.error);
