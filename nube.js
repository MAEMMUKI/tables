/* Maemuki · Nube: guarda los datos de los editores en tu GitHub (rama "datos"), cifrados con tu clave.
   El repositorio es público, por eso todo va cifrado (AES-GCM, clave derivada con PBKDF2).
   En otro aparato solo necesitas la clave: el token viaja cifrado adentro. */
(function(){
  const BRANCH = 'datos';
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = u8 => { let s=''; for (let i=0;i<u8.length;i+=0x8000) s+=String.fromCharCode.apply(null,u8.subarray(i,i+0x8000)); return btoa(s); };
  const unb64 = s => { const b=atob(s.replace(/\s/g,'')); const a=new Uint8Array(b.length); for (let i=0;i<b.length;i++) a[i]=b.charCodeAt(i); return a; };
  async function key(pass, salt){
    const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:310000, hash:'SHA-256'}, base, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
  }
  async function lock(obj, pass){
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, await key(pass, salt), enc.encode(JSON.stringify(obj))));
    return {v:1, salt:b64(salt), iv:b64(iv), data:b64(data)};
  }
  async function unlock(box, pass){
    try {
      const out = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(box.iv)}, await key(pass, unb64(box.salt)), unb64(box.data));
      return JSON.parse(dec.decode(out));
    } catch(e) { throw new Error('La clave no coincide. Escribe la misma clave que usaste para guardar.'); }
  }
  async function api(gh, method, path, body){
    const h = {'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'};
    if (gh.token) h.Authorization = 'Bearer ' + gh.token;
    if (body) h['Content-Type'] = 'application/json';
    const r = await fetch('https://api.github.com' + path, {method, headers:h, body: body ? JSON.stringify(body) : undefined, cache:'no-store'});
    if (r.status === 404 && method === 'GET') return null;
    if (!r.ok) {
      if (r.status === 401) throw new Error('El token no es válido o ya venció.');
      if (r.status === 403) throw new Error(gh.token ? 'El token no tiene permiso para escribir en el repositorio.' : 'GitHub está limitando las consultas. Intenta en unos minutos.');
      if (r.status === 409 || r.status === 422) throw new Error('GitHub rechazó el cambio. Intenta otra vez en unos segundos.');
      throw new Error('GitHub respondió con un error (' + r.status + ').');
    }
    return r.status === 204 ? {} : r.json();
  }
  const repoPath = gh => `/repos/${encodeURIComponent(gh.user)}/${encodeURIComponent(gh.repo)}`;
  async function ensureBranch(gh){
    const b = await api(gh, 'GET', repoPath(gh) + '/git/ref/heads/' + BRANCH);
    if (b) return;
    const repo = await api(gh, 'GET', repoPath(gh));
    const main = await api(gh, 'GET', repoPath(gh) + '/git/ref/heads/' + encodeURIComponent(repo.default_branch || 'main'));
    await api(gh, 'POST', repoPath(gh) + '/git/refs', {ref:'refs/heads/' + BRANCH, sha:main.object.sha});
  }
  async function push(gh, file, obj, pass){
    if (!gh.user || !gh.repo || !gh.token) throw new Error('Para guardar en la nube necesitas tu usuario, repositorio y token de GitHub (una sola vez en este aparato).');
    if (!pass || pass.length < 8) throw new Error('Escribe una clave de al menos 8 letras o números.');
    await ensureBranch(gh);
    const path = repoPath(gh) + '/contents/' + file;
    const cur = await api(gh, 'GET', path + '?ref=' + BRANCH);
    const box = await lock(obj, pass);
    const content = b64(enc.encode(JSON.stringify(box)));
    await api(gh, 'PUT', path, {message:'Nube: ' + file, content, branch:BRANCH, ...(cur && cur.sha ? {sha:cur.sha} : {})});
  }
  async function pull(gh, file, pass){
    if (!gh.user || !gh.repo) throw new Error('Escribe tu usuario y repositorio de GitHub.');
    if (!pass) throw new Error('Escribe tu clave de la nube.');
    const f = await api(gh, 'GET', repoPath(gh) + '/contents/' + file + '?ref=' + BRANCH);
    if (!f || !f.content) return null;
    return unlock(JSON.parse(dec.decode(unb64(f.content))), pass);
  }
  const PASSKEY = 'maemukiClaveNube';
  const getPass = () => { try { return localStorage.getItem(PASSKEY) || ''; } catch(e) { return ''; } };
  const setPass = p => { try { localStorage.setItem(PASSKEY, p); } catch(e) {} };
  window.MaemukiNube = {push, pull, getPass, setPass};
})();
