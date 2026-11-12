/* CT-Watchtower UI.
   Deliberately simple: no framework. Fragments arrive fully rendered from the server;
   what is here is keyboard handling, toasts, polling and the rule form logic. */
'use strict';

const ctw = (() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const tenant = document.body.dataset.tenant || '';
  const qs = (obj) => new URLSearchParams(Object.entries(obj).filter(([, v]) => v !== '' && v != null)).toString();
  let paused = false;

  async function swap(url, el) {
    const res = await fetch(url, { headers: { 'X-Requested-With': 'ctw' } });
    if (!res.ok) throw new Error(res.status);
    el.innerHTML = await res.text();      // server-rendered, escaped HTML
  }

  async function api(method, path, body) {
    const res = await fetch(path, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = res.status === 204 ? null : await res.json().catch(() => null);
    if (!res.ok) {
      const err = new Error((data && data.error) || `HTTP ${res.status}`);
      Object.assign(err, { status: res.status, data });
      throw err;
    }
    return data;
  }

  let toastTimer;
  function toast(msg) {
    const el = $('#toast');
    el.textContent = msg;                  // textContent: never innerHTML for foreign data
    el.hidden = false;
    el.classList.remove('fade');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      el.classList.add('fade');
      setTimeout(() => { el.hidden = true; }, 200);
    }, 2400);                              // 2.4 s, as in the handoff
  }

  function debounce(fn, ms) {
    let t;
    return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  }

  // The findings spectrum sits on Live (per minute) and on Findings (per day). Both
  // resolutions change slowly, so every 20 s instead of on every finding.
  function spectrum() {
    const box = document.getElementById('spectrum-box');
    if (!box) return;
    const load = () => {
      if (paused) return;
      swap(`/ui/spectrum?${qs({ t: tenant, a: box.dataset.resolution })}`, box).catch(() => {});
    };
    // The switch sits in the fragment and is replaced on every load, hence a
    // listener on the container instead of on the buttons.
    box.addEventListener('click', (ev) => {
      const b = ev.target.closest('[data-resolution]');
      if (!b) return;
      box.dataset.resolution = b.dataset.resolution;
      load();
    });
    load();
    setInterval(load, 20000);
  }

  async function setStatus(id, status) {
    const label = {
      confirmed: 'confirmed',
      false_positive: 'marked as a false positive',
      reported: 'marked as reported, it will not be deleted any more',
    }[status] || status;
    toast(`Finding ${label}`);             // optimistic: report first, then write
    try {
      await api('PATCH', `/api/v1/findings/${encodeURIComponent(id)}`, { status });
    } catch (err) {
      toast(`Failed: ${err.message}`);
    }
  }

  // -- Detail panel and enrichment --------------------------
  // Registration data is fetched ONLY here: on deliberately opening the panel with a
  // click. Moving with j/k does not call `openDetail`, otherwise fifty keystrokes
  // would turn into fifty registry queries. Registries allow the single query for
  // display, not the automated sweep (§16).
  const ENRICH_POLL = [1500, 2500, 4000, 6000];

  const closePanel = (host) => { host.innerHTML = ''; };

  function note(host, text, tone) {
    const el = $('#enrich-note', host);
    if (!el) return;
    el.textContent = text;                 // textContent: foreign text never as HTML
    el.hidden = !text;
    if (tone) el.dataset.tone = tone; else delete el.dataset.tone;
  }

  // `quota` holds daily counters and caps per source (rdap/whois/doh), which becomes
  // "rdap 50/50 · doh 200/200". If a part is missing it quietly drops out.
  const quotaText = (q) => Object.entries((q && q.counts) || {})
    .map(([src, n]) => `${src} ${n}/${((q.limits || {})[src]) ?? '?'}`)
    .join(' · ');

  function enrichNote(res) {
    switch (res && res.status) {
      case 'queued':
      case 'pending':
        return ['Registrar and domain age are being queried. The fields appear in a moment.', ''];
      case 'disabled':
        return ['Enrichment is switched off. Registrar, domain age and DNS stay empty.', ''];
      case 'quota':
        return [`The daily cap for enrichment queries is reached. ${quotaText(res.quota)}. The fields stay empty for now.`, 'warn'];
      case 'busy':
        return ['Enrichment is busy right now. Open the panel again later.', 'warn'];
      default:
        return ['', ''];                   // done: the fields are in the panel already
    }
  }

  async function openDetail(id, host) {
    await swap(`/ui/finding/${encodeURIComponent(id)}`, host);   // the panel is there at once
    resumeScanWatch(host);
    let res;
    try {
      res = await api('POST', `/api/v1/findings/${encodeURIComponent(id)}/enrich`);
    } catch (err) {
      return note(host, `Enrichment not possible: ${err.message}`, 'warn');
    }
    note(host, ...enrichNote(res));
    if (res.status === 'queued' || res.status === 'pending') pollEnrich(id, host);
  }

  // Deliberately simple: a short reload of the fragment instead of an SSE
  // subscription. The findings screen holds no stream open at all, and an EventSource
  // of its own per open panel would be more machinery than four timers for a single
  // expected event. If the window is not enough, the panel says so honestly instead
  async function pollEnrich(id, host) {
    for (const ms of ENRICH_POLL) {
      await new Promise((done) => setTimeout(done, ms));
      const open = $('.panel', host);
      if (!open || open.dataset.id !== id) return;              // the panel was closed
      await swap(`/ui/finding/${encodeURIComponent(id)}`, host);
      resumeScanWatch(host);
      const fresh = $('.panel', host);
      if (!fresh || fresh.dataset.enrichState !== 'pending') return;   // done
      note(host, ...enrichNote({ status: 'pending' }));
    }
    note(host, 'The enrichment is taking longer. Close the panel and open it again later.', 'warn');
  }

  // Trigger an analysis at an external service. Deliberately without retries and
  // without a batch call: every click is exactly one submission for exactly one
  // finding. urlscan's result page only comes about once the scan is through; before
  // that it answers 404. So the link we get after triggering is not usable yet, and
  // until then there is an hourglass here.
  const HOURGLASS = '<svg class="hourglass" viewBox="0 0 16 16" aria-hidden="true">'
    + '<path d="M3 1h10v2l-3.6 5 3.6 5v2H3v-2l3.6-5L3 3V1zm2.2 1.6 2.8 4 2.8-4H5.2z'
    + 'M8 9.4l-2.8 4h5.6l-2.8-4z"/></svg>';

  function scanRunning(text) {
    const box = document.createElement('span');
    box.className = 'scan-running';
    box.setAttribute('role', 'status');
    box.innerHTML = HOURGLASS;
    box.appendChild(document.createTextNode(` ${text}`));
    return box;
  }

  function scanLink(service, scan) {
    const a = document.createElement('a');
    a.className = 'btn';
    a.href = scan.result;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = `${service}: result (${scan.visibility})`;
    return a;
  }

  // Keep asking until the service is done. The first time after ten seconds, before
  // which it never is, then every five. After a good two minutes we give up and show
  // the link anyway: better to look yourself than stare at an hourglass forever.
  async function watchScan(holder, id, service, scan) {
    const replace = (el) => { holder.replaceWith(el); holder = el; };
    let waitFor = 10000;
    for (let attempt = 0; attempt < 26; attempt++) {
      await new Promise((f) => setTimeout(f, waitFor));
      waitFor = 5000;
      // Panel closed or fragment reloaded: this hourglass no longer hangs in the
      // document. Then the asking stops too, otherwise opening it several times
      // would run several loops against the same third-party service.
      if (!holder.isConnected) return;
      let d;
      try {
        const r = await fetch(`/api/v1/findings/${id}/scan/${service}`);
        if (!r.ok) break;
        d = await r.json();
      } catch (err) { break; }
      if (d.retry_after) waitFor = Math.min(d.retry_after * 1000, 60000);
      if (d.state === 'done') return replace(scanLink(service, d));
      if (d.state === 'deleted') {
        return replace(scanRunning('The service has removed the result again.'));
      }
      if (d.state === 'error' || d.state === 'unknown') break;
    }
    replace(scanLink(service, scan));
  }

  // When opening a finding whose scan is still running: pick the tracking back up.
  // The state sits on the finding, not in the browser. A closed panel did not abort
  // the hourglass, it only lost sight of it.
  function resumeScanWatch(host) {
    $$('[data-scan-watch]', host).forEach((el) => {
      if (el.dataset.watching) return;
      el.dataset.watching = '1';
      el.insertAdjacentHTML('afterbegin', HOURGLASS);
      watchScan(el, el.dataset.id, el.dataset.scanWatch,
                    { result: el.dataset.result, visibility: el.dataset.visibility });
    });
  }

  async function startScan(btn) {
    const note_el = scanNoteOf(btn);
    btn.disabled = true;
    const before = btn.textContent;
    btn.textContent = 'running ...';
    try {
      const resp = await fetch(`/api/v1/findings/${btn.dataset.id}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service: btn.dataset.scan }),
      });
      const data = await resp.json().catch(() => ({}));
      if (resp.ok && data.scan) {
        const service = btn.dataset.scan;
        if (data.scan.state !== 'running') { btn.replaceWith(scanLink(service, data.scan)); return; }
        const waiting = scanRunning('Scan running. That usually takes half a minute.');
        btn.replaceWith(waiting);
        watchScan(waiting, btn.dataset.id, service, data.scan);
        return;
      }
      if (note_el) note_el.textContent = data.reason || `Failed (HTTP ${resp.status})`;
    } catch (err) {
      if (note_el) note_el.textContent = 'Network error while triggering';
    }
    btn.disabled = false;
    btn.textContent = before;
  }

  function scanNoteOf(btn) {
    return btn.closest('.panel') ? btn.closest('.panel').querySelector('#scan-note') : null;
  }

  // Tick off revocation hits. They have no detail panel; a certificate is revoked or
  // it is not, there is nothing to unfold.
  function bindRevocationHits(root_el, afterwards) {
    root_el.addEventListener('click', async (ev) => {
      const btn_el = ev.target.closest('[data-revocation-hit]');
      if (!btn_el) return;
      ev.stopPropagation();
      try {
        await api('PATCH', `/api/v1/revocations/findings/${btn_el.dataset.revocationHit}`,
                  { status: btn_el.dataset.status });
        if (afterwards) afterwards();
      } catch (e) { toast(e.message); }
    });
  }

  function bindPanel(host, after) {
    host.addEventListener('click', async (ev) => {
      if (ev.target.closest('[data-close]')) return closePanel(host);
      const scan = ev.target.closest('[data-scan]');
      if (scan) return startScan(scan);
      // The exoneration note only disappears for this look; nothing changes on the
      // finding. Whoever clicks it away does not want to read it now, not never.
      if (ev.target.closest('#exoneration-close')) {
        const note_el = $('#exoneration', host);
        if (note_el) note_el.remove();
        return;
      }
      const btn = ev.target.closest('[data-set-status]');
      if (!btn) return;
      closePanel(host);
      await setStatus(btn.dataset.id, btn.dataset.setStatus);
      if (after) after();
    });
  }

  // -- Segmented sliders ------------------------------------
  // The bar is drawn, the native `input` sits underneath and keeps mouse, touch and
  // keyboard. All that happens here is setting the fill as a CSS variable, plus the
  // segment width, so forty segments always stay forty.
  function segmentFill(el) {
    const min = Number(el.min || 0);
    const max = Number(el.max || 100);
    const fraction = max > min ? (Number(el.value) - min) / (max - min) : 0;
    el.style.setProperty('--p', `${Math.max(0, Math.min(1, fraction)) * 100}%`);
  }

  function drawSegments(root = document) {
    $$('input[type="range"]', root).forEach(segmentFill);
  }

  document.addEventListener('input', (ev) => {
    if (ev.target.matches && ev.target.matches('input[type="range"]')) segmentFill(ev.target);
  });

  // -- Shell ------------------------------------------------
  function initShell() {
    drawSegments();
    const defang = $('#defang-toggle');
    if (defang) defang.addEventListener('click', () => {
      const on = defang.getAttribute('aria-pressed') === 'true';
      document.cookie = `ctw_defang=${on ? '0' : '1'}; path=/; max-age=31536000; samesite=lax`;
      location.reload();
    });

    // The tenant switcher is a `details`. Keyboard and the second click come from the
    // browser; only closing on a click elsewhere is missing there.
    const switcher = $('#tenant-switch');
    if (switcher) document.addEventListener('click', (ev) => {
      if (switcher.open && !switcher.contains(ev.target)) switcher.open = false;
    });
    const pause = $('#pause-toggle');
    const liveLamp = $('#an-live');
    const pauseLamp = $('#an-pause');
    // The lamps at the top mirror the state: LIVE goes out on pause, PAUSE lights up
    // amber. Without it there would be no way to see why nothing is coming in.
    const showState = () => {
      if (liveLamp) liveLamp.classList.toggle('on', !paused);
      if (pauseLamp) pauseLamp.classList.toggle('on', paused);
    };
    showState();
    if (pause) pause.addEventListener('click', () => {
      paused = !paused;
      pause.setAttribute('aria-pressed', String(paused));
      if (pauseLamp) pauseLamp.textContent = paused ? 'Resume' : 'Pause';
      showState();
    });
    $$('[data-tenant-pick]').forEach((a) => a.addEventListener('click', () => {
      document.cookie = `ctw_tenant=${a.dataset.tenantPick}; path=/; max-age=31536000; samesite=lax`;
    }));
    document.addEventListener('click', (ev) => {
      const btn = ev.target.closest('[data-copy]');
      if (!btn) return;
      navigator.clipboard.writeText(btn.dataset.copy).then(() => toast('Copied'));
    });
  }

  // -- Live -------------------------------------------------
  function initLive() {
    const rows = $('#live-rows');
    const scroll = $('#live-scroll');
    const search = $('#live-q');
    const slider = $('#live-score');
    const host = $('#panel-host');
    let sel = 0;

    let severity = '';
    const params = () => qs({
      t: tenant, q: search.value.trim(), min_score: slider.value, severity,
    });
    const mark = () => {
      const all = $$('.live-row[data-id]', rows);
      if (!all.length) return;
      sel = Math.max(0, Math.min(sel, all.length - 1));
      all.forEach((r, i) => {
        r.classList.toggle('sel', i === sel);
        r.setAttribute('aria-selected', String(i === sel));
      });
      // So a screen reader reads the selected row without the focus jumping out of
      // the list.
      rows.setAttribute('aria-activedescendant', all[sel].id || '');
      all[sel].scrollIntoView({ block: 'nearest' });
    };
    const reload = async () => {
      if (paused) return;
      try {
        await swap(`/ui/live-rows?${params()}`, rows);
        mark();
        const n = $('[data-count]', rows);
        const count = $('#live-count');
        if (count && n) count.textContent = `${n.dataset.count} · the newest 60`;
        $('#live-state').textContent = '';
      } catch (err) {
        $('#live-state').textContent = 'API unreachable';
      }
    };

    // The counters double as filters: a second click clears the selection again.
    $$('.counter[data-sev]').forEach((b) => b.addEventListener('click', () => {
      severity = severity === b.dataset.sev ? '' : b.dataset.sev;
      $$('.counter[data-sev]').forEach((x) => x.setAttribute(
        'aria-pressed', String(x.dataset.sev === severity)));
      reload();
    }));

    search.addEventListener('input', debounce(reload, 250));
    slider.addEventListener('input', () => { $('#live-score-val').textContent = slider.value; });
    slider.addEventListener('change', reload);
    rows.addEventListener('click', (ev) => {
      // The buttons of the revocation hits sit in the same row. `stopPropagation`
      // does not help here: both handlers hang off the same node and run in the
      // order they were registered.
      if (ev.target.closest('[data-revocation-hit]')) return;
      const row = ev.target.closest('.live-row[data-id]');
      if (!row) return;
      sel = $$('.live-row[data-id]', rows).indexOf(row);
      mark();
      openDetail(row.dataset.id, host);    // a click opens, and only that enriches
    });
    bindPanel(host, reload);
    bindRevocationHits(rows, reload);

    document.addEventListener('keydown', (ev) => {
      if (ev.key === '/' && document.activeElement !== search) {
        ev.preventDefault();
        search.focus();
        return;
      }
      if (document.activeElement === search) {
        if (ev.key === 'Escape') { search.blur(); scroll.focus(); }
        return;
      }
      if (ev.key === 'Escape') { closePanel(host); return; }
      // From here on: pure keyboard triage. j/k only moves, it opens no panel and
      // sets off no enrichment.
      const all = $$('.live-row[data-id]', rows);
      if (!all.length) return;
      if (ev.key === 'j') { sel += 1; mark(); }
      else if (ev.key === 'k') { sel -= 1; mark(); }
      else if (ev.key === 'Enter') {
        // Exactly like a click: one deliberate single action, one enrichment.
        // Without this branch the keyboard reaches every row but never a finding.
        const row = all[sel];
        if (row) { ev.preventDefault(); openDetail(row.dataset.id, host); }
      }
      else if (ev.key === 'c' || ev.key === 'f') {
        const row = all[sel];
        if (!row) return;
        const status = ev.key === 'c' ? 'confirmed' : 'false_positive';
        row.dataset.status = status;
        row.style.opacity = '.5';
        setStatus(row.dataset.id, status);
      }
    });

    reload();
    spectrum();
    // Deliberately simple: SSE is only the nudge. Rendering happens on the server, once.
    const es = new EventSource(`/api/v1/stream?${qs({ tenant })}`);
    const nudge = debounce(reload, 400);
    es.addEventListener('finding', nudge);
    es.addEventListener('open', () => { $('#live-state').textContent = ''; });
    es.addEventListener('error', () => { $('#live-state').textContent = 'Live connection interrupted, retrying'; });
  }

  // -- Findings ---------------------------------------------
  function initFindings() {
    spectrum();
    const rows = $('#findings-rows');
    const host = $('#panel-host');
    const search = $('#findings-q');
    let severity = '';
    let sort = 'first_seen';

    const reload = async () => {
      try {
        await swap(`/ui/findings-rows?${qs({ t: tenant, severity, sort, q: search.value.trim() })}`, rows);
        const n = $('[data-count]', rows);
        $('#findings-count').textContent = n ? n.dataset.count : '0';
      } catch (err) {
        $('#findings-count').textContent = '-';
      }
    };
    $$('#sev-filter button').forEach((b) => b.addEventListener('click', () => {
      severity = b.dataset.sev;
      $$('#sev-filter button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      reload();
    }));
    // Sorting through the column headers. `aria-sort` carries the state so a screen
    // reader reads it out and the styling can pick it up.
    $$('.table thead button[data-sort]').forEach((b) => b.addEventListener('click', () => {
      sort = b.dataset.sort;
      $$('.table thead th').forEach((th) => th.setAttribute(
        'aria-sort', th.contains(b) ? 'descending' : 'none'));
      reload();
    }));
    search.addEventListener('input', debounce(reload, 250));
    rows.addEventListener('click', async (ev) => {
      if (ev.target.closest('[data-revocation-hit]')) return;   // see initLive
      const tr = ev.target.closest('tr[data-id]');
      if (!tr) return;
      await openDetail(tr.dataset.id, host);
    });
    bindPanel(host, reload);
    bindRevocationHits(rows, reload);
    document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closePanel(host); });
    reload();
  }

  // -- Campaigns --------------------------------------------
  function initCampaigns() {
    const list = $('#camp-list');
    const host = $('#panel-host');
    let sort = 'newest';
    let all = false;
    const reload = async () => {
      await swap(`/ui/campaigns?${qs({ t: tenant, sort, all: all ? '1' : '' })}`, list);
      const btn = $('#camp-all', list);
      if (btn) btn.addEventListener('click', () => { all = true; reload(); });
      const n = $('[data-count]', list);
      const num_ = $('#camp-count');
      if (num_ && n) num_.textContent = n.dataset.count;
    };
    $$('#camp-sort button').forEach((b) => b.addEventListener('click', () => {
      sort = b.dataset.sort;
      $$('#camp-sort button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
      reload();
    }));
    // From the cluster into the single finding: before this you saw the campaign and
    // could not reach the domains it is made of.
    list.addEventListener('click', (ev) => {
      const finding = ev.target.closest('.camp-finding[data-id]');
      if (finding) openDetail(finding.dataset.id, host);
    });
    bindPanel(host, reload);
    document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closePanel(host); });
    reload();
  }

  // -- System -----------------------------------------------
  function initSystem() {
    const body = $('#system-body');
    const err = $('#system-error');
    const tick = async () => {
      if (paused) return;
      try {
        await swap('/ui/system', body);
        err.hidden = true;
      } catch (e) {
        // The old values stay. An empty page would be worse than an old one.
        err.textContent = 'The application is unreachable, the values below are stale.';
        err.hidden = false;
      }
    };
    tick();
    setInterval(tick, 4000);

    // The test message sends exactly one real mail, hence no second click while the
    // first is running, and the result in plain words next to it.
    body.addEventListener('click', async (ev) => {
      const btn_el = ev.target.closest('#test-mail');
      if (!btn_el || btn_el.disabled) return;
      const note_el = $('#test-mail-note', body);
      btn_el.disabled = true;
      const before = btn_el.textContent;
      btn_el.textContent = 'sending ...';
      try {
        const res = await api('POST', '/api/v1/system/notify-test');
        if (note_el) note_el.textContent = `Sent to ${res.sent_to.join(', ')} via ${res.route}.`;
        toast('Test message sent');
      } catch (e) {
        if (note_el) note_el.textContent = e.message;
        toast('Test message failed');
      }
      btn_el.textContent = before;
      btn_el.disabled = false;
    });
  }

  // -- Rules ------------------------------------------------
  function initRules() {
    const dialog = $('#tenant-dialog');
    const openDialog = () => { $('#nt-error').textContent = ''; dialog.showModal(); };
    const newBtn = $('#new-tenant');
    if (newBtn) newBtn.addEventListener('click', openDialog);

    $('#tenant-form').addEventListener('submit', async (ev) => {
      if (ev.submitter && ev.submitter.value !== 'ok') return;
      ev.preventDefault();
      const id = $('#nt-id').value.trim();
      try {
        await api('POST', '/api/v1/tenants', { id, name: $('#nt-name').value.trim() || id });
        document.cookie = `ctw_tenant=${id}; path=/; max-age=31536000; samesite=lax`;
        location.href = `/rules?t=${encodeURIComponent(id)}`;
      } catch (e) {
        $('#nt-error').textContent = e.message;
      }
    });

    const stateEl = $('#rule-state');
    if (!stateEl) return;
    const state = JSON.parse(stateEl.textContent);
    const num = (id) => Number($(`#in-${id}`).value);

    // Endings stay a list of their own. They are a property of the name and sit under
    // "The name itself", not with the rules.
    const KINDS = {
      tlds: { list: 'list', max: 60, fresh: () => ({ name: 'own', weight: 25, list: [] }) },
    };
    // Empty groups (all chips removed, or "new group" without a term) drop out.
    const groups = (key) => state.own[key].filter((g) => (g[KINDS[key].list] || []).length);
    const initial = {};
    const touched = new Set();

    // -- One list for everything that hands out points -------
    //
    // In the form there are only "rules" any more. What gets stored is still the
    // shape that matches the meaning. Measured against the golden set, anything else
    //
    //   one line, establishes the brand  -> `anchors`, counts once per rule
    //   one line, otherwise             -> `lures`,   every term found counts
    //   several lines / pattern / NOT   -> `rules`,   counts once per rule
    //
    // Turning a lure group into a single rule across the board took `paylio-login.s3.
    // amazonaws.com` from alert 96 down to warning 66. The conversion happens on
    // save, not while typing. Whoever adds a second line deliberately changes the
    // meaning, and the explanation on the right says so.
    const word = (t) => (typeof t === 'string' ? { text: t, pattern: false } : { ...t });
    const TOLERANT = () => ({
      exact: true, homoglyph: true,
      fuzzy: { enabled: true, max_distance: 1 },
      permutations: { enabled: true },
    });
    const STRICT = () => ({ exact: true, homoglyph: false, fuzzy: { enabled: false }, permutations: { enabled: false } });
    const isTolerant = (m) => !!(m && (m.homoglyph || (m.fuzzy && m.fuzzy.enabled) || (m.permutations && m.permutations.enabled)));

    const fromGroup = (g, anchor) => ({
      name: g.description || (anchor ? 'Brand anchor' : 'Lure terms'),
      weight: g.weight,
      counts_as_anchor: anchor,
      tolerant: anchor ? isTolerant(g.match) : false,
      whole_word: !!g.whole_word,
      rows: [{ terms: (g.terms || []).map(word), negate: false }],
      exclude: g.exclude || [],
      owned_domains: g.owned_domains || [],
      match: g.match || null,
    });

    const rules_ = [
      ...(state.own.anchors || []).map((g) => fromGroup(g, true)),
      ...(state.own.lures || []).map((g) => fromGroup(g, false)),
      ...(state.own.rules || []).map((r) => ({
        name: r.name, weight: r.weight,
        counts_as_anchor: !!r.counts_as_anchor,
        tolerant: r.tolerant !== false,
        rows: (r.all_of || []).map((b) => ({ terms: (b.any_of || []).map(word), negate: !!b.negate })),
        exclude: r.exclude || [], owned_domains: r.owned_domains || [], match: r.match || null,
      })),
      // The old free patterns come along, as a rule with one pattern line.
      ...(state.own.custom || []).map((c) => ({
        name: c.id, weight: c.weight,
        counts_as_anchor: !!c.counts_as_anchor,
        tolerant: false,
        rows: [{ terms: [{ text: c.regex, pattern: true }], negate: false }],
        exclude: [], owned_domains: [], match: null,
      })),
    ];

    const rowsWithContent = (r) => r.rows.filter((z) => z.terms.some((t) => (t.text || '').trim()));
    const valid = () => rules_.filter((r) => (r.name || '').trim() && rowsWithContent(r).some((z) => !z.negate));
    const simple = (r) => {
      const z = rowsWithContent(r);
      return z.length === 1 && !z[0].negate && z[0].terms.every((t) => !t.pattern);
    };

    const splitTerms = () => {
      const anchors = [], lures = [], rules = [];
      valid().forEach((r) => {
        const z = rowsWithContent(r);
        if (simple(r)) {
          const terms = z[0].terms.map((t) => t.text.trim().toLowerCase()).filter(Boolean);
          if (r.counts_as_anchor) {
            anchors.push({
              description: r.name, terms, weight: r.weight,
              match: r.match || (r.tolerant ? TOLERANT() : STRICT()),
              exclude: r.exclude, owned_domains: r.owned_domains,
            });
          } else {
            lures.push({
              description: r.name, terms, weight: r.weight, whole_word: !!r.whole_word,
            });
          }
          return;
        }
        rules.push({
          name: r.name, weight: r.weight,
          counts_as_anchor: r.counts_as_anchor, tolerant: r.tolerant,
          all_of: z.map((row_el) => ({
            any_of: row_el.terms
              .filter((t) => (t.text || '').trim())
              .map((t) => (t.pattern ? { pattern: t.text.trim() } : t.text.trim().toLowerCase())),
            negate: row_el.negate,
          })),
          exclude: r.exclude, owned_domains: r.owned_domains,
        });
      });
      return { anchors, lures, rules };
    };
    let initialRules = '';

    // Suppression: split into `exact` and `suffix` in the file, one list in the form.
    // A leading dot decides where an entry belongs, so nobody has to keep two fields
    // apart, and `.example.com` reads like what it does.
    state.own.allowlist ||= {};
    const sup = (state.own.allowlist.suppress ||= {});
    sup.exact ||= []; sup.suffix ||= [];
    const suppressList = () => [...sup.exact, ...sup.suffix];
    let initialSuppress = '';

    // Captured only AFTER the first draw: drawing fills missing fields with defaults
    // (`match.fuzzy` on a group that had none). Taken before that, the form would
    // take that filling-in for a change by the user and write it back into the file
    // on every save.
    const snapshot = () => {
      Object.keys(KINDS).forEach((key) => { initial[key] = JSON.stringify(groups(key)); });
      initialSuppress = JSON.stringify(suppressList());
      initialRules = JSON.stringify(splitTerms());
    };

    const patch = () => {
      const p = {};
      ['persist', 'warning', 'alert', 'enrich_from'].forEach((k) => {
        if (touched.has(k)) (p.thresholds ||= {})[k] = num(k);
      });
      if (touched.has('anchor_missing_cap')) {
        (p.scoring ||= {}).anchor_missing_cap = num('anchor_missing_cap');
      }
      Object.keys(KINDS).forEach((key) => {
        const now = groups(key);
        if (JSON.stringify(now) === initial[key]) return;
        if (key === 'tlds') p.tlds = { groups: now };
        else p[key] = now;
      });
      if (JSON.stringify(suppressList()) !== initialSuppress) {
        p.allowlist = { suppress: { exact: sup.exact, suffix: sup.suffix } };
      }
      const split = splitTerms();
      if (JSON.stringify(split) !== initialRules) {
        Object.assign(p, split);
        // The old free patterns are rules now, so the old field is emptied,
        // otherwise the same condition would count twice.
        if ((state.own.custom || []).length) p.custom = [];
      }
      // Structure thresholds: only the ones that were moved. Whoever touches one pins
      // it in their own file; the rest still come from the defaults and includes.
      $$('.rule-slider.struct').forEach((el) => {
        if (!touched.has(el.dataset.path)) return;
        const [, detector, field] = el.dataset.path.split('.');
        (((p.structure ||= {})[detector] ||= {}))[field] = Number(el.value);
      });
      return p;
    };

    const el = (tag, cls, text) => {
      const n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text != null) n.textContent = text;   // foreign text never as HTML
      return n;
    };

    // -- The rule building kit -------------------------------
    //
    // One card per rule: name, points, conditions. Terms in one line are OR, lines
    // below each other are AND. There are deliberately no more levels; that gets by
    // without brackets, a tree and dragging, and the explanation on the right stays
    // a readable sentence.
    const chipList = (values, removeEntry, isPattern, withOr = false) => {
      const box = el('div', 'chips');
      const parts = [];
      values.forEach((v, i) => {
        const text = String(v.text ?? v);
        // "or" between the terms: how a line is joined is written nowhere else, and
        // nobody should have to guess it.
        if (withOr && i > 0) parts.push(el('span', 'chip-or', 'or'));
        const chip = el('span', `chip ${isPattern && isPattern(v) ? 'tag-pattern' : ''}`.trim(), text);
        const x = el('button', null, '×');
        x.setAttribute('aria-label', `remove ${text}`);
        x.addEventListener('click', () => removeEntry(i));
        chip.appendChild(x);
        parts.push(chip);
      });
      box.replaceChildren(...parts);
      return box;
    };

    // The same question mark as in the Jinja macro `help()`, built from the script.
    const questionMark = (text) => {
      const d = el('details', 'help');
      d.dataset.help = text;
      const s = el('summary', null, '?');
      s.setAttribute('aria-label', 'Help');
      d.append(s, el('p', null, text));
      return d;
    };

    const drawRow = (rule, row_el, nr) => {
      const box = el('div', 'condition');

      const head = el('div', 'condition-head');
      if (nr > 0) head.appendChild(el('span', 'joiner', 'AND'));
      const kind = el('select', 'input');
      kind.style.cssText = 'padding:3px 6px; font-size:11.5px;';
      [['contains', 'false'], ['does not contain', 'true']].forEach(([text, value]) => {
        const opt = el('option', null, text);
        opt.value = value;
        kind.appendChild(opt);
      });
      kind.value = String(!!row_el.negate);
      kind.setAttribute('aria-label', `Condition ${nr + 1}`);
      kind.addEventListener('change', () => { row_el.negate = kind.value === 'true'; drawRules(); });
      head.appendChild(kind);
      if (rule.rows.length > 1) {
        const gone = el('button', 'copy', '× line');
        gone.title = 'Remove this condition';
        gone.addEventListener('click', () => { rule.rows.splice(nr, 1); drawRules(); });
        head.appendChild(gone);
      }
      box.appendChild(head);

      box.appendChild(chipList(
        row_el.terms,
        (i) => { row_el.terms.splice(i, 1); drawRules(); },
        (t) => t.pattern,
        true,
      ));

      const inputRow = el('div', 'term-new');
      const field = el('input', 'input');
      field.style.cssText = 'flex:1; min-width:110px;';
      field.placeholder = 'Word or pattern';
      const add = (asPattern) => {
        const typed = field.value.trim();
        if (!typed) return;
        const fresh = asPattern
          ? { text: typed, pattern: true }
          : { text: typed.toLowerCase(), pattern: false };
        if (!row_el.terms.some((t) => t.text === fresh.text && t.pattern === fresh.pattern)) {
          row_el.terms.push(fresh);
        }
        field.value = '';
        drawRules();
      };
      const wordButton = el('button', 'btn', '+ word');
      wordButton.addEventListener('click', () => add(false));
      const patternButton = el('button', 'btn', '+ pattern');
      patternButton.title = 'A regular expression, never fuzzed';
      patternButton.addEventListener('click', () => add(true));
      field.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); add(false); } });
      inputRow.append(field, wordButton, patternButton);
      box.appendChild(inputRow);
      return box;
    };

    const drawRule = (rule, index) => {
      const card = el('div', 'rule-card rule-card-box');

      const name = el('input', 'input rule-name');
      name.value = rule.name || '';
      name.placeholder = 'Name of the rule';
      name.setAttribute('aria-label', 'Name of the rule');
      name.addEventListener('input', () => { rule.name = name.value; });
      const head = el('div', 'rule-card-head');
      const nameField = el('label', 'field');
      nameField.append(
        el('span', 'kicker', `Edit rule ${String(index + 1).padStart(2, '0')}`
          + (rule.counts_as_anchor ? ' · anchor · establishes the brand' : ' · counts on top')),
        name,
      );
      head.appendChild(nameField);

      const pointsRow = el('label', 'slider-row');
      const pointsValue = el('b', 'slider-val', String(Math.round(rule.weight)));
      const pointsLabel = el('span', 'label muted');
      pointsLabel.appendChild(el('b', null, 'Points'));
      // How it counts depends on the shape of the rule. That wants explaining, but
      // not as a sentence under every card.
      pointsLabel.appendChild(questionMark(simple(rule)
        ? (rule.counts_as_anchor
          ? 'This rule counts once, even when several of its terms match. Finding the brand twice is not twice as bad.'
          : 'Every term found counts on its own: more matching words, more points. That is how a word list works.')
        : 'Counts once per finding, as soon as every condition is met.'));
      const showPoints = () => {
        pointsValue.textContent = String(Math.round(rule.weight));
        // The bar in the tab list belongs to the same number, it has to move along.
        const bar = $(`.tabs-row:nth-of-type(${index + 1}) .points-bar i`);
        if (bar) bar.style.width = `${Math.max(0, Math.min(100, rule.weight))}%`;
      };
      const slider = el('input', 'rule-slider');
      Object.assign(slider, { type: 'range', min: 0, max: 100, value: rule.weight });
      slider.setAttribute('aria-label', 'Points of this rule');
      slider.addEventListener('input', () => { rule.weight = Number(slider.value); showPoints(); });
      pointsRow.append(pointsLabel, slider, pointsValue);
      showPoints();
      head.appendChild(pointsRow);
      card.appendChild(head);

      card.appendChild(el('div', 'field-label', 'If the domain ...'));
      const rows = el('div', 'conditions');
      rows.replaceChildren(...rule.rows.map((z, i) => drawRow(rule, z, i)));
      card.appendChild(rows);

      const plus = el('button', 'btn', '+ condition (AND)');
      plus.style.marginTop = '8px';
      plus.addEventListener('click', () => {
        rule.rows.push({ terms: [], negate: false });
        drawRules();
      });
      card.appendChild(plus);

      const toggleRow = (text, value, apply, title) => {
        const label = el('label', 'small rule-switch');
        const tick = el('input');
        tick.type = 'checkbox';
        tick.checked = value;
        tick.addEventListener('change', () => { apply(tick.checked); drawRules(); });
        label.append(tick, el('span', null, text));
        if (title) label.title = title;
        return label;
      };
      card.appendChild(toggleRow(
        'Catch spelling variants', rule.tolerant,
        (v) => { rule.tolerant = v; rule.match = null; },
        'Typos, digits for letters, lookalike characters. Off: spelled exactly like this.',
      ));
      card.appendChild(toggleRow(
        'establishes the brand reference', rule.counts_as_anchor,
        (v) => { rule.counts_as_anchor = v; },
        'Without such a rule a finding stays under the cap from step 2.',
      ));
      // Only for simple word rules without a brand reference; there it turns into a
      // lure group, and only that knows `whole_word`.
      if (!rule.counts_as_anchor && simple(rule)) {
        card.appendChild(toggleRow(
          'only as a whole word', rule.whole_word,
          (v) => { rule.whole_word = v; },
          'Off: the term counts anywhere in the name, in "bridgeintelligence" too. On: only where it stands on its own.',
        ));
      }

      const more = el('details', 'exceptions');
      const count = (rule.exclude || []).length + (rule.owned_domains || []).length;
      more.appendChild(el('summary', 'small muted',
        `Exceptions and own domains${count ? ` · ${count} ${count === 1 ? 'entry' : 'entries'}` : ''}`));
      const listField = (key, label, placeholderText) => {
        const box = el('div');
        box.style.marginTop = '8px';
        box.appendChild(el('div', 'field-label', label));
        box.appendChild(chipList(rule[key], (i) => { rule[key].splice(i, 1); drawRules(); }));
        const row_el = el('div');
        row_el.style.cssText = 'display:flex; gap:6px; margin-top:6px;';
        const input_el = el('input', 'input');
        input_el.placeholder = placeholderText;
        input_el.style.cssText = 'flex:1; min-width:0;';
        const btn_el = el('button', 'btn', 'Add');
        const add = () => {
          const v = input_el.value.trim().toLowerCase();
          if (v && !rule[key].includes(v)) rule[key].push(v);
          drawRules();
        };
        btn_el.addEventListener('click', add);
        input_el.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); add(); } });
        row_el.append(input_el, btn_el);
        box.appendChild(row_el);
        return box;
      };
      more.appendChild(listField('exclude', 'Exceptions. They contain the term but do not mean it', 'e.g. an everyday word'));
      more.appendChild(listField('owned_domains', 'Own domains. This rule never counts there', 'e.g. example.com'));
      card.appendChild(more);

      const foot = el('div', 'rule-card-foot');
      const del_ = el('button', 'btn btn-danger rule-del', 'Delete the rule');
      del_.addEventListener('click', () => { rules_.splice(index, 1); drawRules(); });
      foot.appendChild(del_);
      card.appendChild(foot);
      return card;
    };

    // Four cards open at once with up to 25 terms each was no longer readable. Now:
    // a list of all rules, with only the selected one open below it.
    let chosen = 0;

    const tabRow = (rule, index) => {
      const row_el = el('button', 'tabs-row');
      row_el.setAttribute('role', 'listitem');
      row_el.setAttribute('aria-current', String(index === chosen));

      row_el.appendChild(el('span', 'nr', String(index + 1).padStart(2, '0')));

      const name = el('span', 'name');
      name.appendChild(el('b', null, rule.name || 'Unnamed'));
      const terms = rule.rows.reduce((n, z) => n + z.terms.length, 0);
      const extent = `${terms} ${terms === 1 ? 'term' : 'terms'}`
        + ` · ${rule.rows.length} ${rule.rows.length === 1 ? 'condition' : 'conditions'}`;
      name.appendChild(el('span', 'small muted', extent));
      row_el.appendChild(name);

      row_el.appendChild(el(
        'span', rule.counts_as_anchor ? 'tag' : 'tag tag-outline',
        rule.counts_as_anchor ? 'anchor' : 'on top',
      ));

      const points = el('span', 'points-bar');
      const bar = el('span', 'bar');
      const fill = el('i');
      fill.style.width = `${Math.max(0, Math.min(100, rule.weight))}%`;
      bar.appendChild(fill);
      points.append(bar, el('b', null, String(Math.round(rule.weight))));
      row_el.appendChild(points);

      row_el.addEventListener('click', () => { chosen = index; drawRules(); });
      return row_el;
    };

    const drawRules = () => {
      const box = $('[data-rules]');
      const editor = $('[data-rule-editor]');
      if (!box || !editor) return;
      chosen = Math.max(0, Math.min(chosen, rules_.length - 1));

      const head = el('div', 'tabs-head');
      head.setAttribute('aria-hidden', 'true');
      ['No', 'Rule · size', 'Kind', 'Points'].forEach((t) => head.appendChild(el('span', null, t)));
      box.replaceChildren(head, ...rules_.map(tabRow));

      editor.replaceChildren(...(rules_.length ? [drawRule(rules_[chosen], chosen)] : []));
      drawSegments(editor);
      tabSummary();
      proseSoon();
    };

    // Every tab shows its state in short, so nobody has to open it to know it.
    const tabSummary = () => {
      const put = (ident, text) => {
        const target = $(`[data-sum="${ident}"]`);
        if (target) target.textContent = text;
      };
      const anchor = rules_.filter((r) => r.counts_as_anchor).length;
      put('search', `${rules_.length} ${rules_.length === 1 ? 'rule' : 'rules'} · ${anchor} anchors`);
      const num = (id) => { const e = $(`#in-${id}`); return e ? e.value : '-'; };
      put('report', `warning from ${num('warning')} · alert from ${num('alert')}`);
      const sup = (state.own.allowlist || {}).suppress || {};
      const own = (sup.exact || []).length + (sup.suffix || []).length;
      put('never', own ? `${own} of your own` : 'none yet. The first finding is your own website');
      put('name', `${(state.own.tlds || []).length} ending groups`);
    };

    const newRule = $('[data-rule-add]');
    if (newRule) newRule.addEventListener('click', () => {
      rules_.push({
        name: '', weight: 45, counts_as_anchor: rules_.length === 0, tolerant: true, whole_word: false,
        rows: [{ terms: [], negate: false }], exclude: [], owned_domains: [], match: null,
      });
      chosen = rules_.length - 1;
      drawRules();
      const field = $('.rule-name');
      if (field) field.focus();
    });

    // The endings keep their simple group editor, a list with a weight; nothing more
    // is needed there.
    const drawGroups = () => {
      Object.entries(KINDS).forEach(([key, kind]) => {
        const box = $(`[data-groups="${key}"]`);
        if (!box) return;
        if (!state.own[key].length) state.own[key].push(kind.fresh());
        box.replaceChildren(...state.own[key].map((g, i) => {
          const card = el('div', 'group');
          const label = g.description || g.name || `Group ${i + 1}`;
          if (!Array.isArray(g[kind.list])) g[kind.list] = [];
          const terms = g[kind.list];

          // Header of the group: name, points, delete, in one row, like the rule
          // card above it. The slider sits with its value in a `.slider-row`, so the
          // three-column grid works out.
          const head = el('div', 'group-head');
          const name = el('input', 'input rule-name');
          name.value = label;
          name.setAttribute('aria-label', 'Name of the group');
          name.addEventListener('input', () => { g.description = name.value; });

          const sliderRow = el('label', 'slider-row');
          const val = el('b', 'slider-val', String(Math.round(g.weight)));
          const slider = el('input', 'rule-slider');
          Object.assign(slider, {
            type: 'range', min: Math.min(0, g.weight), max: Math.max(kind.max, g.weight), value: g.weight,
          });
          slider.setAttribute('aria-label', `Points: ${label}`);
          slider.addEventListener('input', () => { g.weight = Number(slider.value); val.textContent = slider.value; });
          sliderRow.append(el('span', 'label muted', 'Points'), slider, val);

          const gone = el('button', 'btn btn-danger', 'Delete the group');
          gone.addEventListener('click', () => {
            state.own[key].splice(i, 1);
            drawGroups();
          });
          head.append(name, sliderRow, gone);

          const chips = chipList(terms, (idx) => { terms.splice(idx, 1); drawGroups(); });
          const row = el('div');
          row.style.cssText = 'display:flex; gap:8px; margin-top:6px;';
          const input = el('input', 'input');
          input.style.maxWidth = '220px';
          input.placeholder = 'e.g. top';
          const btn = el('button', 'btn', 'Add');
          const add = () => {
            const term = input.value.trim().toLowerCase().replace(/^\./, '');
            if (term && !terms.includes(term)) terms.push(term);
            drawGroups();
          };
          btn.addEventListener('click', add);
          input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); add(); } });
          row.append(input, btn);

          card.append(head, chips, row);
          segmentFill(slider);
          return card;
        }));
      });
    };

    $$('[data-group-add]').forEach((btn) => btn.addEventListener('click', () => {
      state.own[btn.dataset.groupAdd].push(KINDS[btn.dataset.groupAdd].fresh());
      drawGroups();
    }));

    $$('.rule-slider').forEach((el) => el.addEventListener('input', () => {
      // The key from the id, not from `data-path`: the id carries it anyway, and
      // `val-`/`scale-` hang off it. Through `data-path` template and script drifted
      // apart: the threshold sliders were called `thresholds.persist` there while the
      // check was for `persist`, and threshold changes were quietly dropped.
      const key = el.id.slice(3);
      touched.add(key);
      // getElementById instead of querySelector: the structure paths contain dots a
      // selector would read as classes (`#val-structure.hyphen_count` is a class!).
      const out = document.getElementById(`val-${key}`);
      if (out) out.textContent = el.value;
      const scale = document.getElementById(`scale-${key}`);
      if (scale) scale.style.left = `${el.value}%`;
    }));

    // -- What should never be reported -----------------------
    const drawSuppress = () => {
      const box = $('[data-suppress]');
      if (!box) return;
      const chips = el('div', 'chips');
      chips.style.marginBottom = '10px';
      chips.replaceChildren(...suppressList().map((entry) => {
        const chip = el('span', 'tag tag-neutral', entry);
        chip.style.display = 'inline-flex';
        chip.style.gap = '6px';
        const x = el('button', 'copy', '×');
        x.title = 'Remove';
        x.addEventListener('click', () => {
          sup.exact = sup.exact.filter((t) => t !== entry);
          sup.suffix = sup.suffix.filter((t) => t !== entry);
          drawSuppress();
        });
        chip.appendChild(x);
        return chip;
      }));
      const row = el('div');
      row.style.cssText = 'display:flex; gap:8px;';
      const input = el('input', 'input');
      input.style.maxWidth = '260px';
      input.placeholder = 'example.com or .example.com';
      const btn = el('button', 'btn', 'Add');
      const add = () => {
        const value = input.value.trim().toLowerCase();
        if (value && !suppressList().includes(value)) (value.startsWith('.') ? sup.suffix : sup.exact).push(value);
        drawSuppress();
        $('[data-suppress] input.input').focus();
      };
      btn.addEventListener('click', add);
      input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); add(); } });
      row.append(input, btn);
      box.replaceChildren(chips, row);
    };

    // Disabling and switching back on go the same way as every rule change: a PATCH
    // on the tenant file. Then a reload, so bar and button match.
    $('#toggle-tenant').addEventListener('click', async (ev) => {
      const on = ev.currentTarget.dataset.enabled !== 'true';
      try {
        await api('PATCH', `/api/v1/tenants/${encodeURIComponent(state.tenant)}/rules`,
                  { tenant: { enabled: on } });
        location.reload();
      } catch (e) {
        toast(`Not changed: ${e.message}`);
      }
    });

    // -- Saving ----------------------------------------------

    $('#rules-save').addEventListener('click', async () => {
      try {
        const p = patch();
        if (!Object.keys(p).length) { toast('No changes'); return; }
        await api('PATCH', `/api/v1/tenants/${encodeURIComponent(state.tenant)}/rules`, p);
        snapshot();
        touched.clear();
        toast('Rules saved');
      } catch (e) {
        toast(`Not saved: ${e.message}`);
      }
    });

    // Deleting: a simple confirmation first; if the API answers 409 (the tenant has
    // findings), the same dialog shows the number and demands the typed tenant id.
    const del = $('#delete-dialog');
    const ack = $('#dd-ack');
    let confirm = false;
    ack.addEventListener('input', () => {
      $('#dd-ok').disabled = ack.value.trim() !== $('#dd-id').textContent;
    });
    $('#del-tenant').addEventListener('click', (ev) => {
      confirm = false;
      $('#dd-id').textContent = ev.currentTarget.dataset.id;   // textContent: foreign text never as HTML
      $('#dd-findings').hidden = true;
      $('#dd-error').textContent = '';
      ack.value = '';
      $('#dd-ok').disabled = false;
      $('#dd-ok').textContent = 'Delete';
      del.showModal();
    });
    $('#delete-form').addEventListener('submit', async (ev) => {
      if (ev.submitter && ev.submitter.value !== 'ok') return;
      ev.preventDefault();
      const id = $('#dd-id').textContent;
      try {
        const query = confirm ? `?confirm=${encodeURIComponent(id)}` : '';
        await api('DELETE', `/api/v1/tenants/${encodeURIComponent(id)}${query}`);
        location.href = '/rules';
      } catch (e) {
        if (e.status === 409 && !confirm && e.data && Number.isInteger(e.data.findings)) {
          confirm = true;
          $('#dd-count').textContent = e.data.findings.toLocaleString('en-GB');
          $('#dd-findings').hidden = false;
          $('#dd-ok').textContent = 'Delete for good';
          $('#dd-ok').disabled = true;
        } else {
          $('#dd-error').textContent = e.message;
        }
      }
    });

    const runTest = async () => {
      const res = await fetch('/ui/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: $('#test-domain').value.trim(), tenant: state.tenant, patch: patch() }),
      });
      $('#test-result').innerHTML = res.ok ? await res.text() : 'Scoring failed';
    };
    $('#test-run').addEventListener('click', runTest);
    $('#test-domain').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') runTest(); });

    // -- Tabs ------------------------------------------------
    // Four steps instead of one long column. The right-hand column stays for all of
    // them, so all that changes here is what is visible on the left.
    const tab_el = $$('.tab');
    const showTab = (ident) => {
      tab_el.forEach((t) => {
        const active = t.dataset.tab === ident;
        t.setAttribute('aria-selected', String(active));
        t.tabIndex = active ? 0 : -1;
        document.getElementById(`panel-${t.dataset.tab}`).hidden = !active;
      });
      try {
        localStorage.setItem('ctw_rules_tab', ident);
      } catch (e) { /* a private window: then without a memory */ }
    };
    tab_el.forEach((t) => t.addEventListener('click', () => showTab(t.dataset.tab)));
    // Arrow keys as usual in a tab list (WAI-ARIA).
    $('.tabs').addEventListener('keydown', (ev) => {
      const direction = {
        ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1, Home: -99, End: 99,
      }[ev.key];
      if (!direction) return;
      ev.preventDefault();
      const now = tab_el.findIndex((t) => t.getAttribute('aria-selected') === 'true');
      const target = Math.abs(direction) > 1
        ? (direction > 0 ? tab_el.length - 1 : 0)
        : (now + direction + tab_el.length) % tab_el.length;
      showTab(tab_el[target].dataset.tab);
      tab_el[target].focus();
    });
    try {
      const remembered = localStorage.getItem('ctw_rules_tab');
      if (remembered && tab_el.some((t) => t.dataset.tab === remembered)) showTab(remembered);
    } catch (e) { /* see above */ }

    // -- "What you built" ------------------------------------
    // The explanation comes from the server, out of the validated ruleset. Rebuilt in
    // the browser it would sooner or later run beside the engine.
    const proseBox = $('#prose-content');
    let proseRun = 0;
    const fetchProse = async () => {
      const run = ++proseRun;
      try {
        const res = await fetch(`/api/v1/tenants/${encodeURIComponent(state.tenant)}/rules/validate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(patch()),
        });
        const data = await res.json();
        if (run !== proseRun) return;  // a newer answer is already here
        if (!data.valid) {
          proseBox.replaceChildren(el('p', 'small', data.error || 'The ruleset is invalid'));
          proseBox.firstChild.style.color = 'var(--color-warn)';
          return;
        }
        const block = (a) => {
          const box = el('div', `paragraph ${a.kind}`);
          if (a.title) box.appendChild(el('h4', null, a.title));
          a.rows.forEach((z) => box.appendChild(el('p', null, z)));
          return box;
        };
        // Fold the inherited groups away: they cannot be edited here and would
        // otherwise push everything of your own out of sight.
        const own = data.prose.filter((a) => a.kind !== 'inherited');
        const inherited = data.prose.filter((a) => a.kind === 'inherited');
        const parts = own.map(block);
        if (inherited.length) {
          const fold = el('details', 'paragraph inherited');
          fold.appendChild(el('summary', 'small muted',
            `${inherited.length} more groups come in through includes`));
          inherited.map(block).forEach((b) => fold.appendChild(b));
          // Before the sentence about the thresholds, so that one stays last.
          parts.splice(Math.max(parts.length - 1, 0), 0, fold);
        }
        proseBox.replaceChildren(...parts);
      } catch (e) {
        if (run === proseRun) proseBox.replaceChildren(el('p', 'small muted', 'The explanation is unreachable'));
      }
    };
    // Batched: typing in a chip field would otherwise mean one request per keystroke.
    let proseTimer = 0;
    const proseSoon = () => {
      clearTimeout(proseTimer);
      proseTimer = setTimeout(fetchProse, 400);
    };

    // Listen only inside the rules area: otherwise every keystroke in the test field
    // would set off a rescoring of the whole ruleset.
    const redraw = () => proseSoon();
    const range = $('.rules-shell > div');
    range.addEventListener('input', redraw);
    range.addEventListener('click', (ev) => { if (ev.target.closest('button')) redraw(); });

    drawRules();
    drawGroups();
    drawSuppress();
    snapshot();
    fetchProse();
  }

  // -- Settings ---------------------------------------------
  function initSettings() {
    initRevocationList();
    const form = $('#settings-form');
    const state = $('#settings-state');
    const report = (text, kind) => {
      if (!state) return;
      state.textContent = text;
      state.className = kind === 'error' ? 'error' : 'unsaved';
    };

    // Only what was touched gets sent. Sending everything would mean writing every
    // value into the database, the ones deliberately coming from `.env` included.
    const touched = new Set();
    form.addEventListener('input', (ev) => {
      const field = ev.target.closest('[data-name]');
      if (!field) return;
      touched.add(field.dataset.name);
      if (field.dataset.kind === 'bool') {
        const word = field.closest('.switch')?.querySelector('span');
        if (word) word.textContent = field.checked ? 'on' : 'off';
      }
      report('Unsaved changes');
    });

    const read = (field) => {
      if (field.dataset.kind === 'bool') return field.checked;
      if (field.dataset.kind === 'int' || field.dataset.kind === 'float') return Number(field.value);
      return field.value;
    };

    const send = async (payload, successText) => {
      try {
        await api('PUT', '/api/v1/settings', payload);
        toast(successText);
        // A reload instead of keeping count in our head: the page shows per field
        // where the value comes from, and the server works that out, not the browser.
        location.reload();
      } catch (e) {
        report(e.message, 'error');
        toast('Not saved');
      }
    };

    $('#settings-save').addEventListener('click', () => {
      const payload = {};
      touched.forEach((name) => {
        const field = $(`[data-name="${name}"]`, form);
        if (!field) return;
        // An empty secret means "unchanged", not "delete", otherwise a password
        // would lose its value as soon as somebody changed something else.
        if (field.dataset.kind === 'secret' && !field.value) return;
        payload[name] = read(field);
      });
      if (!Object.keys(payload).length) { toast('No changes'); return; }
      send(payload, 'Settings saved');
    });

    // Reset: `null` throws the entry away, afterwards `.env` applies again.
    form.addEventListener('click', (ev) => {
      const btn_el = ev.target.closest('[data-reset]');
      if (!btn_el) return;
      send({ [btn_el.dataset.reset]: null }, 'Reset to .env');
    });
  }

  // -- Revoked CA certificates ------------------------------
  function initRevocationList() {
    const list_el = $('#revocation');
    if (!list_el) return;
    const note = $('#revocation-note', list_el);
    const say = (t) => { if (note) note.textContent = t; };

    const sync = $('#revocation-sync', list_el);
    sync.addEventListener('click', async () => {
      sync.disabled = true;
      const before = sync.textContent;
      sync.textContent = 'fetching ...';
      try {
        const r = await api('POST', '/api/v1/revocations/sync');
        toast(r.status === 'unchanged'
          ? 'Unchanged, nothing to fetch'
          : `${r.imported} entries imported`);
        location.reload();
      } catch (e) {
        say(e.message);
        sync.disabled = false;
        sync.textContent = before;
      }
    });

    $('#revocation-add', list_el).addEventListener('click', async () => {
      const value = $('#revocation-value', list_el).value.trim();
      if (!value) { say('It does not work without a value.'); return; }
      try {
        await api('POST', '/api/v1/revocations', {
          kind: $('#revocation-kind', list_el).value,
          value,
          name: $('#revocation-name-input', list_el).value,
          reason: $('#revocation-reason', list_el).value,
        });
        toast('Added');
        location.reload();
      } catch (e) { say(e.message); }
    });

    list_el.addEventListener('click', async (ev) => {
      const off = ev.target.closest('[data-revocation-toggle]');
      const gone = ev.target.closest('[data-revocation-del]');
      if (!off && !gone) return;
      try {
        if (gone) {
          await api('DELETE', `/api/v1/revocations/${gone.dataset.revocationDel}`);
        } else {
          await api('PATCH', `/api/v1/revocations/${off.dataset.revocationToggle}`,
                    { active: off.dataset.active !== '1' });
        }
        location.reload();
      } catch (e) { say(e.message); }
    });

    // Searching and filtering in the browser: over a thousand rows are in the
    // document already, asking the server again for that would be nonsense.
    const search_el = $('#revocation-search', list_el);
    const mine = $('#revocation-only-own', list_el);
    const rows = $$('.revocation-row', list_el);
    const filter_ = () => {
      const word = search_el.value.trim().toLowerCase();
      const only = mine.checked;
      rows.forEach((z) => {
        const matches_ = (!word || z.dataset.search.includes(word))
                   && (!only || z.dataset.source === 'manual');
        z.hidden = !matches_;
      });
    };
    search_el.addEventListener('input', filter_);
    mine.addEventListener('change', filter_);
  }

  // Start the screen from `body[data-screen]` instead of an inline script per page.
  // That way the UI gets by without `script-src 'unsafe-inline'` (CSP, see app.py).
  const screens = { live: initLive, findings: initFindings, campaigns: initCampaigns,
                    system: initSystem, rules: initRules, settings: initSettings };

  document.addEventListener('DOMContentLoaded', () => {
    initShell();
    const start = screens[document.body.dataset.screen];
    if (start) start();
  });

  return { initLive, initFindings, initCampaigns, initSystem, initRules, initSettings, toast };
})();
