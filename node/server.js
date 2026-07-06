// The REAL entrypoint — `npm start` / `node server.js` serves the app (the export's documented run command
// must actually run; an app module that only exports and exits is the bug class this file closes).
import { makeServer } from './src/app.js';

const port = parseInt(process.env.PORT || '8080', 10);
// Bind LOOPBACK by default: a dev/test server should not listen on every interface (it also makes desktop
// firewalls prompt on every run). Deployments set HOST=0.0.0.0 (or the pod IP) explicitly.
const host = process.env.HOST || '127.0.0.1';
makeServer().listen(port, host, () => console.log(`listening on ${host}:${port}`));
