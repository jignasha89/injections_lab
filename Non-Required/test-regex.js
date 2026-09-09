const payload = '"><script>alert(1)</script>';
const body = `<html><body><input type="text" value=""><script>alert(1)</script>"></body></html>`;

function escapeRegex(str) {
  return str.replace(/[.*+?^$\\{\\}()|[\\]\\\\]/g, '\\$&');
}

const escaped = escapeRegex(payload);
console.log("Escaped:", escaped);

const breakoutRegex = new RegExp(`=(['"]).*?${escaped}`, 'i');
console.log("Breakout match:", body.match(breakoutRegex) !== null);

const attrContext = new RegExp(`=(['"])[^\\1>]*?${escaped}.*?\\1`, 'i');
console.log("Attr context match:", attrContext.test(body));
