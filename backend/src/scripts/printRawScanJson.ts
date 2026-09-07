import * as fs from 'fs';
import * as path from 'path';
import { analyzeUrl } from '../services/scannerService';

const url = 'http://testfire.net/bank/login.aspx?uid=admin&btnSubmit=Login';
console.log('Running analyzeUrl for:', url);

const result = analyzeUrl(url);

const outputPath = path.join(__dirname, 'raw_scan_output.json');
fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');

console.log('Wrote raw JSON output to:', outputPath);
console.log('Raw JSON String:');
console.log(JSON.stringify(result, null, 2));
