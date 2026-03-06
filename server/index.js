const port = 5688;
const REMOTE_URL = 'https://fiddler.gasconnect.x10.mx';

(() => {
  console.info('========== Fiddler-everywhere-enhance (Cloud Edition) start ==========');
  const { app, BrowserWindow, shell } = require('electron');
  const path = require('path');
  const fs = require('fs');
  const sp = require('child_process');
  
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

  const originalOpenExternal = shell.openExternal;
  shell.openExternal = (url, options) => {
    if (url.includes('identity.getfiddler.com') || url.includes('127.0.0.1:5678')) {
      return require('electron').shell.openExternal(`${REMOTE_URL}/oauth/authorize`, options);
    }
    return require('electron').shell.openExternal(url, options);
  };

  const originalBrowserWindow = BrowserWindow;
  const hookBrowserWindow = (OriginalBrowserWindow) => {
    function HookedBrowserWindow(options) {
      if (options) {
        options.frame = false;
        if (options.webPreferences) options.webPreferences.devTools = true;
      }
      return new OriginalBrowserWindow(options);
    }
    HookedBrowserWindow.prototype = Object.create(OriginalBrowserWindow.prototype);
    HookedBrowserWindow.prototype.constructor = HookedBrowserWindow;
    Object.setPrototypeOf(HookedBrowserWindow, OriginalBrowserWindow);
    return HookedBrowserWindow;
  };
  const HookedBrowserWindow = hookBrowserWindow(originalBrowserWindow);

  const ModuleLoadHook = {
    electron: (module) => { return { ...module, BrowserWindow: HookedBrowserWindow, shell: shell }; }
  };
  const { Module } = require("module");
  const original_load = Module._load;
  Module._load = (...args) => {
    const loaded_module = original_load(...args);
    if (ModuleLoadHook[args[0]]) return ModuleLoadHook[args[0]](loaded_module);
    return loaded_module;
  };
  
  const originloadURL = BrowserWindow.prototype.loadURL;
  BrowserWindow.prototype.loadURL = function(...args){
    this.setMinimumSize(300, 300);
    if (args[0] && args[0].includes('index.html')) {
      const index = fs.readFileSync(path.resolve(__dirname, './WebServer/ClientApp/dist/index.html')).toString();
      const match = index.match(/main.*?\.js/);
      if (match) {
        const mainXJsPath = path.resolve(__dirname, `./WebServer/ClientApp/dist/${match[0]}`);
        let mainXJs = fs.readFileSync(mainXJsPath).toString();
        mainXJs = mainXJs.replace(/https:\/\/api\.getfiddler\.com/g, `http://127.0.0.1:${port}/api.getfiddler.com`);
        mainXJs = mainXJs.replace(/https:\/\/identity\.getfiddler\.com/g, `http://127.0.0.1:${port}/identity.getfiddler.com`);
        fs.writeFileSync(mainXJsPath, mainXJs);
      }
    }
    return originloadURL.apply(this, args);
  };
})();

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
    
    if (url.pathname === '/auth-callback') {
      const token = url.searchParams.get('token');
      if (token) {
          fs.writeFileSync(tokenFile, token);
          require('electron').BrowserWindow.getAllWindows().forEach(w => w.reload());
      }
      res.setHeader('Content-Type', 'text/html');
      res.end("<h1>Conectado a la Nube. Regresa a Fiddler.</h1><script>setTimeout(window.close, 1000)</script>");
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
    
    proxyReq.on('error', (e) => {
      console.error('[PROXY ERROR]', e);
      res.statusCode = 502;
      res.end();
    });

    req.pipe(proxyReq);
  }).listen(port);
})();
