const port = 5678;
const REMOTE_URL = 'https://fiddler.gasconnect.x10.mx';

(() => {
  console.info('========== Fiddler-everywhere-enhance (Cloud Edition) start ==========');
  const { app, BrowserWindow, shell } = require('electron');
  const path = require('path');
  const fs = require('fs');
  const sp = require('child_process');
  
  // 1. Bypass Seguridad (El truco de msojocs para evitar el Error 252)
  const originalSpwan = sp.spawn;
  sp.spawn = function(...args) {
    if (args[0] && args[0].includes('Fiddler.WebUi')) {
      const pkg = path.resolve(__dirname, '../package.json');
      const data = JSON.parse(fs.readFileSync(pkg).toString());
      data.main = "out/main.original.js";
      fs.writeFileSync(pkg, JSON.stringify(data, null, 4));
    }
    return originalSpwan.apply(this, args);
  };

  app.on('quit', () => {
    const pkg = path.resolve(__dirname, '../package.json');
    const data = JSON.parse(fs.readFileSync(pkg).toString());
    data.main = "out/main.js";
    fs.writeFileSync(pkg, JSON.stringify(data, null, 4));
  });

  // 2. Redirección de Login Directa a la Nube (Evita Errores SSL locales)
  shell.openExternal = (url, options) => {
    if (url.includes('identity.getfiddler.com') || url.includes('127.0.0.1')) {
      return require('electron').shell.openExternal(`${REMOTE_URL}/oauth/authorize`, options);
    }
    return require('electron').shell.openExternal(url, options);
  };

  const original_load = require("module")._load;
  require("module")._load = (...args) => {
    const loaded = original_load(...args);
    if (args[0] === 'electron') return { ...loaded, shell: shell };
    return loaded;
  }
})();

// 3. Servidor de Firma y Relay a tu PHP
(async () => {
  const http = require('http');
  const https = require('https');
  const path = require('path');
  const fs = require('fs');
  const { subtle } = require('crypto').webcrypto;

  const key = await subtle.generateKey({ name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256', length: 256 }, true, ['sign', 'verify']);
  const pubKey = await subtle.exportKey('spki', key.publicKey);
  const priKey = await subtle.exportKey('pkcs8', key.privateKey);

  http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    const tokenFile = path.resolve(require('electron').app.getPath('userData'), 'fiddler_session.token');
    
    // Captura del Token desde el navegador
    if (url.pathname === '/auth-callback') {
      const token = url.searchParams.get('token');
      if (token) {
          fs.writeFileSync(tokenFile, token);
          require('electron').BrowserWindow.getAllWindows().forEach(w => { if(w.webContents.getURL().includes('index.html')) w.reload(); });
      }
      res.setHeader('Content-Type', 'text/html');
      res.end("<h1>Login Exitoso. Fiddler esta sincronizando...</h1><script>setTimeout(window.close, 1500)</script>");
      return;
    }

    const activeToken = fs.existsSync(tokenFile) ? fs.readFileSync(tokenFile, 'utf8').trim() : '';

    const proxyOptions = {
      method: req.method,
      headers: { ...req.headers, host: new URL(REMOTE_URL).host, 'X-Fiddler-Auth': activeToken }
    };

    const proxyReq = https.request(REMOTE_URL + url.pathname + url.search, proxyOptions, async (pRes) => {
      let chunks = [];
      pRes.on('data', c => chunks.push(c));
      pRes.on('end', async () => {
        const body = Buffer.concat(chunks);
        res.statusCode = pRes.statusCode;
        Object.keys(pRes.headers).forEach(h => { if(h.toLowerCase()!=='content-length') res.setHeader(h, pRes.headers[h]); });

        if (pRes.headers['content-type'] && pRes.headers['content-type'].includes('application/json')) {
          const bodyStr = body.toString('utf8');
          const headers = { 'content-type': 'application/json; charset=utf-8' };
          const signData = Object.keys(headers).map(k => `${k}:${headers[k]}`).join('\n') + bodyStr;
          const signPriKey = await subtle.importKey('pkcs8', priKey, { name: "ECDSA", namedCurve: "P-256" }, true, ['sign']);
          const signature = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signPriKey, Buffer.from(signData, 'binary'));
          const len = Buffer.from(new Uint8Array(4)); len.writeInt32BE(pubKey.byteLength);
          const sigHeader = Buffer.concat([new Uint8Array(len), new Uint8Array(pubKey), new Uint8Array(signature)]);
          res.setHeader('Signature', `SignedHeaders=content-type, Signature=${sigHeader.toString('base64')}`);
        }
        res.end(body);
      });
    });
    proxyReq.on('error', () => { res.statusCode = 502; res.end(); });
    req.pipe(proxyReq);
  }).listen(port);
})();

require('./main.original.js');
