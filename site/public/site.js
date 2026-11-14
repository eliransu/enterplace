// Gantry website. No dependencies. Each block is independent and does nothing on a page without its elements.
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const root = document.documentElement;

  // Header: border once scrolled, dropdowns, the phone sheet.
  const hdr = $('#hdr');
  const onScroll = () => hdr.classList.toggle('scrolled', scrollY > 8);
  onScroll();
  addEventListener('scroll', onScroll, { passive: true });

  const menus = $$('.nav-btn');
  const closeMenus = (except) => menus.forEach((b) => b !== except && b.setAttribute('aria-expanded', 'false'));
  menus.forEach((b) => b.addEventListener('click', () => {
    const open = b.getAttribute('aria-expanded') === 'true';
    closeMenus(b);
    b.setAttribute('aria-expanded', String(!open));
  }));
  const burger = $('.burger');
  const sheet = (open) => {
    hdr.classList.toggle('open', open);
    burger.setAttribute('aria-expanded', String(open));
    root.style.overflow = open ? 'hidden' : '';
  };
  burger.addEventListener('click', () => sheet(!hdr.classList.contains('open')));
  document.addEventListener('click', (e) => { if (!e.target.closest('.nav-item')) closeMenus(); });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const open = menus.find((b) => b.getAttribute('aria-expanded') === 'true');
    closeMenus();
    if (open) open.focus();
    if (hdr.classList.contains('open')) { sheet(false); burger.focus(); }
  });
  matchMedia('(min-width: 1081px)').addEventListener('change', () => sheet(false));

  // Theme: follows the system until the visitor picks one.
  $('.theme').addEventListener('click', () => {
    const now = root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    root.dataset.theme = now === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem('theme', root.dataset.theme); } catch (e) { /* private mode: the choice lasts for this page */ }
  });

  // Tables become blocks on a phone, and each cell needs its column name there.
  $$('.tbl').forEach((t) => {
    const names = $$('thead th', t).map((th) => th.textContent.trim());
    $$('tbody tr', t).forEach((tr) => [...tr.children].forEach((td, i) => { if (i && names[i]) td.dataset.l = names[i]; }));
  });

  // Runs fn(true|false) as the element enters and leaves the viewport.
  const watch = (el, fn, margin = '0px') => new IntersectionObserver(([e]) => fn(e.isIntersecting), { rootMargin: margin }).observe(el);

  // The gate. The page ships the end state: one disc per lane and four records.
  // With motion allowed, the same requests are replayed one at a time and each writes its record.
  const hex = () => Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0');
  $$('[data-gate]').forEach((gate) => {
    const data = JSON.parse($('script', gate).textContent);
    if (still || !gate.animate) return;
    gate.classList.add('live');
    const tracks = $$('.lane-track', gate);
    $$('.runner', gate).forEach((r) => r.remove());
    $$('.lane-stop', gate).forEach((l) => l.classList.remove('on'));
    const list = $('.records', gate);
    const pause = $('.gate-pause', gate);
    let n = data.n, prev = data.last, i = 0, seen = false, paused = false;

    const record = ([, who, team, verdict, meta]) => {
      const hash = hex();
      const li = document.createElement('li');
      li.className = 'new';
      li.innerHTML = `<span>#${++n}</span><span class="r-who">${who}<i>${team}</i></span><span class="v v-${verdict}">${verdict}</span><span class="r-meta">${meta}</span><span class="r-hash">${prev} ← ${hash}</span>`;
      prev = hash;
      list.lastElementChild.remove();
      list.prepend(li);
    };

    const launch = () => {
      if (!seen || paused || document.hidden) return;
      const req = data.seq[i++ % data.seq.length];
      const track = tracks[req[0]];
      const gx = getComputedStyle(gate).getPropertyValue('--gx').trim();
      const atGate = `translateX(calc(${gx} - 30px))`;
      const end = 'translateX(calc(100% - 16px))';
      const runner = document.createElement('span');
      runner.className = 'runner';
      const disc = runner.appendChild(document.createElement('span'));
      disc.className = 'disc';
      track.append(runner);
      const gone = () => runner.remove();
      runner.animate([{ transform: 'translateX(0)', opacity: 0 }, { opacity: 1, offset: 0.15 }, { transform: atGate, opacity: 1 }],
        { duration: 1200, easing: 'cubic-bezier(0.3, 0, 0.5, 1)', fill: 'forwards' }).finished.then(() => {
        record(req);
        if (req[3] === 'allow' || req[3] === 'masked') {
          disc.style.background = 'var(--lime)';
          runner.animate([{ transform: atGate, opacity: 1 }, { transform: end, opacity: 1, offset: 0.85 }, { transform: end, opacity: 0 }],
            { duration: 1700, easing: 'cubic-bezier(0.3, 0, 0.3, 1)', fill: 'forwards' }).finished.then(gone);
        } else {
          disc.style.background = 'var(--flame)';
          let label = $('.lane-stop', track);
          if (!label) { label = track.appendChild(document.createElement('span')); label.className = 'lane-stop'; }
          label.textContent = req[5];
          label.classList.add('on');
          setTimeout(() => {
            label.classList.remove('on');
            runner.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 300, fill: 'forwards' }).finished.then(gone);
          }, 2800);
        }
      });
    };
    watch(gate, (v) => { seen = v; });
    setInterval(launch, 1350);
    setTimeout(launch, 300);
    pause.addEventListener('click', () => {
      paused = !paused;
      pause.textContent = paused ? 'Play' : 'Pause';
      pause.setAttribute('aria-pressed', String(paused));
    });
  });

  // The request path: pick an outcome, watch the request go down the stages and stop where it is refused.
  $$('[data-path]').forEach((path) => {
    const cases = JSON.parse($('script', path).textContent);
    const steps = $$('.path-steps li', path);
    const buttons = $$('.path-pick button', path);
    const title = $('.path-out h3', path), text = $('.path-out p', path), out = $('.path-out pre', path);
    const recordStep = steps.findIndex((s) => s.dataset.step === 'record');
    let run = 0;
    const play = (key, instant) => {
      const c = cases[key], mine = ++run;
      buttons.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.case === key)));
      steps.forEach((s) => { s.className = ''; });
      title.textContent = c.title;
      text.textContent = c.text;
      out.innerHTML = c.out;
      const last = c.stop === null ? steps.length - 1 : c.stop;
      const mark = (k) => {
        if (mine !== run) return;
        if (k > last) {
          // A refused request skips the later checks, but the record is still written.
          steps.forEach((s, j) => { if (j > last) s.className = j === recordStep ? 'pass' : 'skip'; });
          return;
        }
        steps[k].className = k === c.stop ? 'stop' : 'pass';
        instant ? mark(k + 1) : setTimeout(() => mark(k + 1), 170);
      };
      mark(0);
    };
    let played = false;
    buttons.forEach((b) => b.addEventListener('click', () => { played = true; play(b.dataset.case, still); }));
    play(buttons[0].dataset.case, true);
    if (!still) {
      watch(path, (v) => { if (v && !played) { played = true; play(buttons[0].dataset.case, false); } }, '0px 0px -30% 0px');
    }
  });

  // Marks which section the reader is in: the five-step rail and the contents list on Learn pages.
  const follow = (links, apply) => {
    const targets = links.map((a) => document.getElementById(a.getAttribute('href').slice(1)));
    if (!targets.length) return;
    let queued = false;
    const update = () => {
      queued = false;
      let cur = -1;
      targets.forEach((t, k) => { if (t.getBoundingClientRect().top < innerHeight * 0.4) cur = k; });
      apply(cur);
    };
    addEventListener('scroll', () => { if (!queued) { queued = true; requestAnimationFrame(update); } }, { passive: true });
    update();
  };
  const railLinks = $$('.rail a');
  follow(railLinks, (cur) => railLinks.forEach((a, k) => { a.parentElement.className = k < cur ? 'done' : k === cur ? 'now' : ''; }));
  const tocLinks = $$('.toc a');
  follow(tocLinks, (cur) => tocLinks.forEach((a, k) => a.classList.toggle('now', k === Math.max(cur, 0))));
})();
