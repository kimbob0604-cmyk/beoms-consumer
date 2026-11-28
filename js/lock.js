// 배포본 잠금 (publish.py 가 배포본에서만 LOCKED 를 true 로 바꾼다 — 이 컴퓨터의 로컬 화면은 잠기지 않는다)
// - 소비재 데이터(data/consumer.json 등)는 AES-256-GCM 으로 잠긴 <이름>.enc 로 올라간다. 처음 열 때 암호를 묻고,
//   PBKDF2 로 만든 열쇠를 이 기기(localStorage)에 기억한다. 암호가 바뀌면(salt 가 바뀌면) 다시 묻는다.
// - 종목 패널 데이터(차트·리포트·수급·공시·펀더, quotes·names)는 범스보드 공개 사이트(같은 github.io 주소의 beoms-dashboard)에서 읽는다.
// - fetch 를 한 겹 감싸서 위 둘을 처리하므로 util.js·stock.js·consumer.js 는 고치지 않는다. util.js 보다 먼저 읽혀야 한다.
(() => {
  const LOCKED = true;
  if (!LOCKED) return;
  const DASH = '../beoms-dashboard/';
  const OWN = new Set(['consumer.json', 'consumer_calls.json', 'trends.json', 'naver_trends.json', 'news.json', 'altdata.json']);
  const orig = window.fetch.bind(window);
  const b64 = t => Uint8Array.from(atob(t), c => c.charCodeAt(0));
  let keyP = null;

  function unlock() {
    if (keyP) return keyP;
    keyP = (async () => {
      const lock = await (await orig(`data/lock.json?t=${Math.floor(Date.now() / 60000)}`, { cache: 'no-store' })).json();
      const salt = b64(lock.salt), chk = b64(lock.check);
      const ok = async k => { try { await crypto.subtle.decrypt({ name: 'AES-GCM', iv: chk.slice(0, 12) }, k, chk.slice(12)); return true; } catch (e) { return false; } };
      const id = 'consumer.key.' + lock.salt.slice(0, 8);
      try {
        const saved = localStorage.getItem(id);
        if (saved) { const k = await crypto.subtle.importKey('raw', b64(saved), 'AES-GCM', false, ['decrypt']); if (await ok(k)) return k; }
      } catch (e) { /* 저장 안 되는 브라우저 */ }
      if (document.readyState === 'loading') await new Promise(r => document.addEventListener('DOMContentLoaded', r, { once: true }));
      return new Promise(resolve => {
        const box = document.createElement('div');
        box.className = 'cs-lock';
        box.innerHTML = `<form class="card"><h2>Beom's Consumer</h2><p class="muted small">암호를 넣으면 이 기기에 기억합니다.</p>
          <input type="password" id="cs-lock-pw" autocomplete="current-password" placeholder="암호" autofocus><button type="submit">열기</button>
          <p class="small down" id="cs-lock-msg"></p></form>`;
        document.body.appendChild(box);
        box.querySelector('form').onsubmit = async ev => {
          ev.preventDefault();
          const msg = box.querySelector('#cs-lock-msg');
          msg.textContent = '확인 중…';
          const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(box.querySelector('#cs-lock-pw').value), 'PBKDF2', false, ['deriveKey']);
          const k = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: lock.iter }, base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
          if (!(await ok(k))) { msg.textContent = '암호가 맞지 않습니다.'; return; }
          try { localStorage.setItem(id, btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', k))))); } catch (e) { /* 이번만 */ }
          box.remove();
          resolve(k);
        };
      });
    })();
    return keyP;
  }

  window.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const m = /^(?:\.\/)?data\/([^?#]+)(\?[^#]*)?$/.exec(url);
    if (!m) return orig(input, init);
    const [, name, qs = ''] = m;
    if (!OWN.has(name)) return orig(`${DASH}data/${name}${qs}`, init);        // 종목 패널 → 범스보드 공개 사이트
    const k = await unlock();
    const r = await orig(`data/${name}.enc${qs}`, init);
    if (!r.ok) return r;                                                        // 올리지 않은 파일(altdata 등) → 그 카드는 숨는다
    const b = new Uint8Array(await r.arrayBuffer());
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, k, b.slice(12));
    return new Response(plain, { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  unlock();
})();
