const port = 5688;
const REMOTE_URL = 'https://fiddler.gasconnect.x10.mx';

(() => {
  console.info('========== Fiddler-everywhere-enhance (Cloud Dynamic) start ==========');
  const { app, BrowserWindow, shell } = require('electron');
  const path = require('path');
  const fs = require('fs');
  const sp = require('child_process');
  
  // 1. Bypass de Seguridad del motor .NET (Intercambio de package.json)
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

  // 2. Redirección de Login (Evita Errores SSL en el navegador)
  shell.openExternal = (url, options) => {
    if (url.includes('identity.getfiddler.com') || url.includes('127.0.0.1')) {
      const authUrl = `${REMOTE_URL}/oauth/authorize`;
      console.log(`[LOGIN] Redirecting to: ${authUrl}`);
      return require('electron').shell.openExternal(authUrl, options);
    }
    return require('electron').shell.openExternal(url, options);
  };

  // 3. Inyectar configuración de Electron (Bypass SSL Local)
  app.on('ready', () => {
    app.commandLine.appendSwitch('ignore-certificate-errors');
  });

  const original_load = require("module")._load;
  require("module")._load = (...args) => {
    const loaded = original_load(...args);
    if (args[0] === 'electron') return { ...loaded, shell: shell };
    return loaded;
  }
})();

// 4. Servidor Gateway (Proxy + Firma ECDSA)
(async () => {
  const http = require('http');
  const https = require('https');
  const path = require('path');
  const fs = require('fs');
  const { subtle } = require('crypto').webcrypto;

  // Generar llaves de firma al vuelo (Fiddler las valida)
  const key = await subtle.generateKey({ name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256', length: 256 }, true, ['sign', 'verify']);
  const pubKey = await subtle.exportKey('spki', key.publicKey);
  const priKey = await subtle.exportKey('pkcs8', key.privateKey);

  http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    const tokenFile = path.resolve(require('electron').app.getPath('userData'), 'fiddler_session.token');
    
    if (url.pathname === '/auth-callback') {
      const token = url.searchParams.get('token');
      if (token) {
          fs.writeFileSync(tokenFile, token);
          require('electron').BrowserWindow.getAllWindows().forEach(w => w.reload());
      }
      res.setHeader('Content-Type', 'text/html');
      res.end("<h1>Conectado a Fiddler Cloud</h1><script>setTimeout(window.close, 1000)</script>");
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
        
        Object.keys(pRes.headers).forEach(h => {
          if(h.toLowerCase() !== 'content-length') res.setHeader(h, pRes.headers[h]);
        });

        if (pRes.headers['content-type'] && pRes.headers['content-type'].includes('application/json')) {
          const bodyStr = body.toString('utf8');
          const headers = { 'content-type': 'application/json; charset=utf-8' };
          const signData = Object.keys(headers).map(k => `${k}:${headers[k]}`).join('\n') + bodyStr;
          const signPriKey = await subtle.importKey('pkcs8', priKey, { name: "ECDSA", namedCurve: "P-256" }, true, ['sign']);
          const signature = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signPriKey, Buffer.from(signData, 'binary'));
          
          const len = Buffer.from(new Uint8Array(4));
          len.writeInt32BE(pubKey.byteLength);
          const sigHeader = Buffer.concat([new Uint8Array(len), new Uint8Array(pubKey), new Uint8Array(signature)]);
          
          res.setHeader('Signature', `SignedHeaders=content-type, Signature=${sigHeader.toString('base64')}`);
        }
        res.end(body);
      });
    });
    proxyReq.on('error', (e) => { res.statusCode = 502; res.end(); });
    req.pipe(proxyReq);
  }).listen(port);
})();

require('./main.original.js');
