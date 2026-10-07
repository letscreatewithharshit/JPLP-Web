'use strict';
/* Builds a single self-contained demo page (dist/jlpl-demo.html) that runs without the server. */
const fs = require('node:fs'), path = require('node:path');
const pub = p => fs.readFileSync(path.join(__dirname, 'public', p), 'utf8');
let html = pub('index.html');
const fonts = '<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&family=Noto+Sans+Devanagari:wght@400;600&display=swap" rel="stylesheet">';
const css = pub('app.css').replace(/@font-face\{[^}]*\}\n?/g, '');
html = html.replace('<link rel="manifest" href="manifest.webmanifest">', '')
  .replace(/<link rel="(icon|apple-touch-icon)"[^>]*>/g, '')
  .replace('<link rel="stylesheet" href="app.css">', fonts + '<style>' + css + '</style>')
  .replace('<script src="app.js"></script>', () => '<script>' + pub('app.js').replace(/<\/script/gi, '<\\/script') + '</script>');
fs.mkdirSync(path.join(__dirname, 'dist'), { recursive: true });
fs.writeFileSync(path.join(__dirname, 'dist', 'jlpl-demo.html'), html);
console.log('Wrote dist/jlpl-demo.html');
