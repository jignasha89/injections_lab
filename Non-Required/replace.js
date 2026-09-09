const fs = require('fs');
const path = require('path');

function walk(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  list.forEach((file) => {
    file = path.join(dir, file);
    const stat = fs.statSync(file);
    if (stat && stat.isDirectory()) { 
      results = results.concat(walk(file));
    } else if (file.endsWith('.tsx') || file.endsWith('.ts')) {
      results.push(file);
    }
  });
  return results;
}

const files = walk('C:/Users/bhima/Desktop/Injection Lab/frontend/src');

files.forEach(file => {
  let content = fs.readFileSync(file, 'utf8');
  let newContent = content
    .replace(/bg-\[\#111520\]/g, 'bg-surface-base')
    .replace(/bg-\[\#07090e\]/g, 'bg-bg-base')
    .replace(/border-\[\#1e2433\]/g, 'border-border-subtle')
    .replace(/rounded-xl/g, 'rounded-md')
    .replace(/rounded-2xl/g, 'rounded-lg')
    .replace(/hover:bg-gradient-to-r hover:from-cyan-500 hover:to-indigo-500/g, 'hover:bg-surface-hover')
    .replace(/hover:shadow-\[.*?\]/g, '')
    .replace(/shadow-inner/g, '')
    .replace(/shadow-sm/g, '')
    .replace(/shadow-md/g, '')
    .replace(/shadow-lg/g, '')
    .replace(/shadow-xl/g, '')
    .replace(/shadow-2xl/g, '')
    .replace(/bg-cyan-500\/10/g, 'bg-brand-primary/10')
    .replace(/text-cyan-[45]00/g, 'text-brand-primary')
    .replace(/border-cyan-500\/[0-9]+/g, 'border-brand-primary/20')
    .replace(/hover:border-cyan-[45]00\/[0-9]+/g, 'hover:border-border-strong')
    .replace(/hover:border-blue-[45]00\/[0-9]+/g, 'hover:border-border-strong')
    .replace(/focus:border-cyan-[45]00\/[0-9]+/g, 'focus:border-border-focus')
    .replace(/focus:ring-cyan-[45]00\/[0-9]+/g, 'focus:ring-border-focus');

  if (content !== newContent) {
    fs.writeFileSync(file, newContent, 'utf8');
    console.log('Updated ' + file);
  }
});
