// Screenshots and the product-tour recording for the README.
//
//   node capture.mjs                     # stills -> $OUT/<name>.png + $OUT/shots.json
//   node capture.mjs --tour              # tour   -> $OUT/tour/f*.jpg + $OUT/tour/frames.json
//   node capture.mjs --record gif-soc    # a short clip: gif-soc, gif-portal, gif-triage (or all)
//
// gif-triage changes the alert it plays with (status, assignee): record it last, re-seed after.
//
// Runs against a seeded instance (seed_demo.py): the analyst frontend at APP_URL and the
// Customer Portal at PORTAL_URL, both proxying /api to the backend. Logs in through the UI
// like a user. See README.md in this directory for the whole pipeline.
//
// Environment:
//   SEED_JSON    the JSON seed_demo.py printed (logins and the ids of the featured items)
//   APP_URL      default http://127.0.0.1:7101
//   PORTAL_URL   default http://127.0.0.1:7102
//   OUT          default ./out
//   THEMES       default "dark,light" (stills only; the tour is dark)
//   ONLY         comma-separated shot names, to re-take a few
//   CHROMIUM     an explicit Chromium executable, when Playwright's own is not installed

import fs from 'node:fs/promises';
import path from 'node:path';
import {chromium} from 'playwright';

const APP_URL = process.env.APP_URL || 'http://127.0.0.1:7101';
const PORTAL_URL = process.env.PORTAL_URL || 'http://127.0.0.1:7102';
const OUT = path.resolve(process.env.OUT || 'out');
const THEMES = (process.env.THEMES || 'dark,light').split(',').map((t) => t.trim()).filter(Boolean);
const ONLY = process.env.ONLY ? new Set(process.env.ONLY.split(',').map((s) => s.trim())) : null;
// --record tour | gif-triage | gif-soc | gif-portal | all (comma-separated); --tour = --record tour
const recordArg = process.argv.indexOf('--record');
const RECORD = recordArg > 0 ? process.argv[recordArg + 1] : process.argv.includes('--tour') ? 'tour' : null;

if (!process.env.SEED_JSON) {
  console.error('Set SEED_JSON to the file seed_demo.py printed (python seed_demo.py seed > seed.json).');
  process.exit(1);
}
const seed = JSON.parse(await fs.readFile(process.env.SEED_JSON, 'utf8'));
const ids = seed.ids;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Things that are not the product: Vite's Vue DevTools button, toasts, the AI chat launcher
// (it overlaps the page edge), scrollbars. The sidebar's Health block reports the demo's
// missing Wazuh/Graylog/MinIO, which says nothing about the product, so it goes too.
const CLEANUP = () => {
  const css = `
    #__vue-devtools-container__, .vue-devtools__anchor, .ai-chatbot-button-wrapper,
    .n-message-container, .n-notification-container { display: none !important; }
    * { scrollbar-width: none !important; }
    *::-webkit-scrollbar { width: 0 !important; height: 0 !important; display: none !important; }
    .n-scrollbar-rail { opacity: 0 !important; }
  `;
  const apply = () => {
    if (!document.getElementById('readme-cleanup')) {
      const style = document.createElement('style');
      style.id = 'readme-cleanup';
      style.textContent = css;
      document.head.appendChild(style);
    }
    for (const label of document.querySelectorAll('.text-2xs.uppercase')) {
      if (label.textContent.trim() === 'Health') {
        const block = label.parentElement && label.parentElement.parentElement;
        if (block && block.style.display !== 'none') block.style.display = 'none';
      }
    }
  };
  const start = () => {
    apply();
    new MutationObserver(apply).observe(document.documentElement, {childList: true, subtree: true});
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
};

// A visible cursor for the recording: a dot that follows the mouse and pulses on click.
const CURSOR = () => {
  const start = () => {
    const dot = document.createElement('div');
    dot.id = 'readme-cursor';
    Object.assign(dot.style, {
      position: 'fixed', left: '-100px', top: '-100px', width: '22px', height: '22px', marginLeft: '-11px',
      marginTop: '-11px', borderRadius: '50%', background: 'rgba(255, 255, 255, 0.92)',
      border: '2px solid rgba(20, 22, 26, 0.85)', boxShadow: '0 2px 10px rgba(0, 0, 0, 0.45)',
      zIndex: '2147483647', pointerEvents: 'none',
    });
    document.documentElement.appendChild(dot);
    // The pointer jumps (one mouse event per move); the dot travels there on a CSS transition.
    const travel = 'left 560ms cubic-bezier(.45, 0, .2, 1), top 560ms cubic-bezier(.45, 0, .2, 1), transform 120ms ease-out';
    let placed = false;
    window.addEventListener('mousemove', (e) => {
      if (!placed) {
        dot.style.transition = 'none';
        dot.style.left = `${e.clientX}px`;
        dot.style.top = `${e.clientY}px`;
        void dot.offsetWidth;
        dot.style.transition = travel;
        placed = true;
        return;
      }
      dot.style.left = `${e.clientX}px`;
      dot.style.top = `${e.clientY}px`;
    }, true);
    window.addEventListener('mousedown', () => { dot.style.transform = 'scale(0.7)'; }, true);
    window.addEventListener('mouseup', () => { dot.style.transform = 'scale(1)'; }, true);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
};

async function newContext(browser, theme, {cursor = false, scale = 2} = {}) {
  const context = await browser.newContext({
    viewport: {width: 1440, height: 900},
    deviceScaleFactor: scale,
    colorScheme: theme,
    timezoneId: 'UTC',
    locale: 'en-US',
  });
  await context.addInitScript(CLEANUP);
  if (cursor) await context.addInitScript(CURSOR);
  return context;
}

async function loginApp(page) {
  await page.goto(`${APP_URL}/login`, {waitUntil: 'domcontentloaded'});
  await page.getByPlaceholder('Insert your username').fill(seed.admin.username);
  await page.getByPlaceholder('Insert your password').fill(seed.admin.password);
  await page.getByRole('button', {name: /sign in with password/i}).click();
  await page.waitForURL((u) => !u.pathname.includes('/login'), {timeout: 30000});
}

async function loginPortal(page) {
  await page.goto(`${PORTAL_URL}/login`, {waitUntil: 'domcontentloaded'});
  await page.getByPlaceholder('Insert your Username').fill(seed.portal_user.username);
  await page.getByPlaceholder('Insert your password').fill(seed.portal_user.password);
  await page.keyboard.press('Enter');
  await page.waitForURL((u) => !u.pathname.includes('/login'), {timeout: 30000});
}

// Network quiet, no spinner or skeleton on screen, then time for charts to finish animating.
async function settle(page, extra = 1500) {
  await page.waitForLoadState('networkidle', {timeout: 20000}).catch(() => undefined);
  await page.waitForFunction(() => {
    const visible = (el) => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
    };
    const busy = [...document.querySelectorAll('.n-spin-body, .n-spin-content--spinning, .n-skeleton, .n-base-loading__container')].filter(visible);
    return busy.length === 0;
  }, null, {timeout: 20000}).catch(() => console.warn('  (still busy after 20 s)'));
  await sleep(extra);
}

async function tab(page, label) {
  await page.locator('.n-tabs-tab').filter({hasText: new RegExp(`^\\s*${label}\\s*$`)}).first().click();
}

async function resetCaseFilter(page) {
  await page.locator('.n-badge .n-button').last().click();
  await page.getByRole('button', {name: 'Reset', exact: true}).click();
  await settle(page, 400);
  const close = page.getByRole('button', {name: 'Close', exact: true});
  if (await close.isVisible().catch(() => false)) await close.click();
}

const APP_SHOTS = [
  {name: 'alerts', path: '/incident-management/alerts'},
  {name: 'alert-detail', path: `/incident-management/alerts/${ids.hero_alert}`, then: (p) => tab(p, 'Overview')},
  {name: 'alert-ai', path: `/incident-management/alerts/${ids.hero_alert}`, then: (p) => tab(p, 'AI Analyst')},
  // The cases list opens filtered on the first customer; reset it to show every customer.
  {name: 'cases', path: '/incident-management/cases', then: resetCaseFilter},
  {name: 'case-detail', path: `/incident-management/cases/${ids.hero_case}`, then: (p) => tab(p, 'Timeline')},
  {name: 'soc-overview', path: '/soc-management'},
  {name: 'soc-sla', path: '/soc-management?tab=sla'},
  {name: 'soc-workload', path: '/soc-management?tab=workload'},
  {name: 'customers', path: '/customers'},
];
const PORTAL_SHOTS = [
  {name: 'portal-overview', path: '/overview'},
  {name: 'portal-alerts', path: '/alerts'},
  {name: 'portal-ai-report', path: `/alerts/${ids.hero_alert}`, then: (p) => tab(p, 'AI Report')},
  {name: 'portal-sla', path: '/sla'},
];

async function shoot(page, base, shot, theme, manifest, app) {
  if (ONLY && !ONLY.has(shot.name)) return;
  console.log(`${theme} ${shot.name} <- ${shot.path}`);
  await page.goto(`${base}${shot.path}`, {waitUntil: 'domcontentloaded'});
  await settle(page, 800);
  if (shot.then) {
    await shot.then(page);
    await settle(page);
  } else {
    await sleep(700);
  }
  await page.mouse.move(1439, 120);
  await sleep(300);
  const name = theme === 'dark' ? shot.name : `${shot.name}-light`;
  const file = `${name}.png`;
  await page.screenshot({path: path.join(OUT, file)});
  manifest.push({name, file, path: shot.path, app, theme});
}

async function stills() {
  await fs.mkdir(OUT, {recursive: true});
  const browser = await chromium.launch({executablePath: process.env.CHROMIUM || undefined});
  const manifest = [];
  try {
    for (const theme of THEMES) {
      const context = await newContext(browser, theme);
      const page = await context.newPage();
      await loginApp(page);
      for (const shot of APP_SHOTS) await shoot(page, APP_URL, shot, theme, manifest, 'app');
      await loginPortal(page);
      for (const shot of PORTAL_SHOTS) await shoot(page, PORTAL_URL, shot, theme, manifest, 'portal');
      await context.close();
    }
  } finally {
    await browser.close();
  }
  const manifestPath = path.join(OUT, 'shots.json');
  let previous = [];
  try {
    previous = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  } catch {
    // first run
  }
  const merged = new Map(previous.map((s) => [s.name, s]));
  for (const s of manifest) merged.set(s.name, s);
  await fs.writeFile(manifestPath, JSON.stringify([...merged.values()], null, 2));
  console.log(`wrote ${manifest.length} captures to ${OUT}`);
}

// ---- the tour ---------------------------------------------------------------------------

const TRAVEL_MS = 620;

// The pointer to the middle of a locator (the cursor dot glides there), then a click.
async function glide(page, target, {click = true, pause = 180} = {}) {
  // Off screen: scroll it into view smoothly first.
  const handle = await target.elementHandle({timeout: 10000});
  const visible = await handle.evaluate((el) => {
    const r = el.getBoundingClientRect();
    return r.top >= 0 && r.bottom <= innerHeight;
  });
  if (!visible) {
    await handle.evaluate((el) => el.scrollIntoView({behavior: 'smooth', block: 'center'}));
    await sleep(800);
  }
  const box = await target.boundingBox({timeout: 10000});
  if (!box) throw new Error('target not visible');
  const x = box.x + box.width / 2;
  const y = box.y + box.height / 2;
  await page.mouse.move(x, y);
  await sleep(TRAVEL_MS + pause);
  if (click) await page.mouse.click(x, y);
}

async function moveTo(page, x, y) {
  await page.mouse.move(x, y);
  await sleep(TRAVEL_MS);
}

// Smooth scrolling of whatever scrolls under the pointer (the page, a modal, a panel).
async function scroll(page, dy) {
  await page.evaluate((delta) => {
    const dot = document.getElementById('readme-cursor');
    const x = dot ? parseFloat(dot.style.left) : innerWidth / 2;
    const y = dot ? parseFloat(dot.style.top) : innerHeight / 2;
    let el = document.elementFromPoint(x, y);
    while (el && el !== document.body) {
      const style = getComputedStyle(el);
      if (/(auto|scroll)/.test(style.overflowY) && el.scrollHeight > el.clientHeight + 4) break;
      el = el.parentElement;
    }
    (el && el !== document.body ? el : document.scrollingElement).scrollBy({top: delta, behavior: 'smooth'});
  }, dy);
  await sleep(700);
}

// Records one script: frames as the browser paints them, with loading time cut out (`cut`).
async function record(name, startUrl, script) {
  const dir = path.join(OUT, name);
  await fs.rm(dir, {recursive: true, force: true});
  await fs.mkdir(dir, {recursive: true});
  const browser = await chromium.launch({executablePath: process.env.CHROMIUM || undefined});
  const context = await newContext(browser, 'dark', {cursor: true, scale: 1});
  const page = await context.newPage();
  await loginPortal(page);
  if (!startUrl.startsWith(PORTAL_URL)) await loginApp(page);
  await page.goto(startUrl, {waitUntil: 'domcontentloaded'});
  await settle(page, 500);
  await page.mouse.move(980, 560);

  const cdp = await context.newCDPSession(page);
  const frames = [];
  const cuts = [];
  const writes = [];
  let n = 0;
  cdp.on('Page.screencastFrame', (frame) => {
    cdp.send('Page.screencastFrameAck', {sessionId: frame.sessionId}).catch(() => undefined);
    const file = `f${String(n++).padStart(5, '0')}.jpg`;
    const url = new URL(page.url());
    const app = url.origin === new URL(PORTAL_URL).origin ? 'portal' : 'app';
    frames.push({file, wall: frame.metadata.timestamp, path: url.pathname, app});
    writes.push(fs.writeFile(path.join(dir, file), Buffer.from(frame.data, 'base64')));
  });
  const cut = async (fn) => {
    const from = Date.now() / 1000;
    await fn();
    cuts.push([from, Date.now() / 1000]);
    // A fresh frame right after the cut, even when nothing else moves.
    const pos = await page.evaluate(() => {
      const d = document.getElementById('readme-cursor');
      return d ? [parseFloat(d.style.left) || 700, parseFloat(d.style.top) || 450] : [700, 450];
    });
    await page.mouse.move(pos[0] + 1, pos[1] + 1);
    await sleep(60);
  };
  const started = Date.now();
  const helpers = {
    page,
    hold: sleep,
    cut,
    loaded: (extra = 300) => cut(() => settle(page, extra)),
    // A tab by its label, a count badge after it allowed ("Workload 3").
    tabTo: async (label) => glide(page, page.locator('.n-tabs-tab').filter({hasText: new RegExp(`^\\s*${label}(\\s+\\d+)?\\s*$`)}).first()),
    mark: (label) => console.log(`  ${((Date.now() - started) / 1000).toFixed(1)} s  ${label}`),
  };

  await cdp.send('Page.startScreencast', {format: 'jpeg', quality: 92, maxWidth: 1440, maxHeight: 900, everyNthFrame: 1});
  await moveTo(page, 985, 565);
  await script(helpers);
  await cdp.send('Page.stopScreencast');
  await Promise.all(writes);

  // Drop what was painted during a cut and close the gap it leaves.
  const inCut = (w) => cuts.some(([a, b]) => w > a && w < b);
  const removedBefore = (w) => cuts.reduce((acc, [a, b]) => acc + (w >= b ? b - a : 0), 0);
  const kept = frames.filter((f) => !inCut(f.wall));
  const t0 = kept[0].wall;
  const timeline = kept.map((f) => ({file: f.file, t: f.wall - t0 - removedBefore(f.wall) + removedBefore(t0), path: f.path, app: f.app}));
  for (const f of frames) if (inCut(f.wall)) await fs.rm(path.join(dir, f.file), {force: true});
  await fs.writeFile(path.join(dir, 'frames.json'), JSON.stringify(timeline, null, 1));
  const cutTotal = cuts.reduce((acc, [a, b]) => acc + (b - a), 0);
  console.log(`${name}: ${timeline.length} frames, ${timeline.at(-1).t.toFixed(1)} s (${cutTotal.toFixed(1)} s of loading cut) in ${dir}`);
  await browser.close();
}

// ~30 s: alerts, an alert and its AI report, its case, SOC Management, the Customer Portal.
async function tour({page, hold, cut, loaded, tabTo, mark}) {
  await hold(1200);

  mark('alerts');
  const card = page.locator('.card-entity').filter({hasText: 'Mimikatz credential dumping'}).first();
  await glide(page, card.getByText('Mimikatz credential dumping').first(), {click: false});
  await hold(400);
  // The card's own View (its footer), not an asset's: the quick view, the AI report first.
  await glide(page, card.locator('.n-button-group').last().getByRole('button', {name: /view/i}));
  await loaded(500);
  await hold(1000);
  await moveTo(page, 760, 600);
  await scroll(page, 280);
  await hold(1300);
  await scroll(page, -280);
  await hold(300);

  mark('alert page');
  const modal = page.locator('.n-modal').last();
  await glide(page, modal.getByLabel("Open the alert's page").first()).catch(async () => {
    await page.goto(`${APP_URL}/incident-management/alerts/${ids.hero_alert}`);
  });
  await loaded();
  await hold(400);
  await tabTo('Overview');
  await loaded(200);
  await hold(1400);

  mark('case');
  await glide(page, page.locator('code', {hasText: `#${ids.hero_case}`}).first());
  await hold(1000);
  await glide(page, page.getByRole('button', {name: 'Open Case'}).first()).catch(async () => {
    await page.goto(`${APP_URL}/incident-management/cases/${ids.hero_case}`);
  });
  await loaded();
  await hold(300);
  await tabTo('Timeline');
  await loaded(200);
  await moveTo(page, 900, 420);
  await hold(1500);

  mark('soc');
  await glide(page, page.getByText('SOC Management', {exact: true}).first());
  await loaded(100);
  await moveTo(page, 980, 400);
  await hold(2200);
  await tabTo('SLA');
  await loaded(100);
  await moveTo(page, 1040, 560);
  await hold(2000);

  mark('portal');
  await cut(async () => {
    await page.goto(`${PORTAL_URL}/overview`, {waitUntil: 'domcontentloaded'});
    await settle(page, 600);
    await page.mouse.move(980, 420);
  });
  await hold(1300);
  await moveTo(page, 760, 640);
  await hold(400);
  await scroll(page, 320);
  await hold(2200);
}

// ~10 s: triage an alert whose response clock is running out, from the alerts list's quick
// view (the list provides the assignable users): status, then assignee.
async function clipTriage({page, hold, loaded}) {
  await hold(1000);
  const card = page.locator('.card-entity').filter({hasText: `#${ids.risk_alert} - `}).first();
  await glide(page, card.locator('.n-button-group').last().getByRole('button', {name: /view/i}));
  await loaded(400);
  await hold(1200);
  const modal = page.locator('.n-modal').last();
  await glide(page, modal.locator('[data-testid=alert-status-trigger]').first());
  await hold(500);
  await glide(page, page.locator('.n-base-select-option').filter({hasText: 'In progress'}).first());
  await loaded(400);
  await moveTo(page, 720, 470);
  await hold(1300);
  await glide(page, modal.locator('.cursor-pointer').filter({hasText: 'n/d'}).first());
  await hold(500);
  await glide(page, page.locator('.n-base-select-option').filter({hasText: 'jkim'}).first());
  await loaded(400);
  await moveTo(page, 720, 470);
  await hold(1800);
}

// ~9 s: SOC Management's period and tabs.
async function clipSoc({page, hold, loaded, tabTo}) {
  await hold(1200);
  await glide(page, page.getByText('7d', {exact: true}).first());
  await loaded(100);
  await moveTo(page, 980, 420);
  await hold(1400);
  await glide(page, page.getByText('30d', {exact: true}).first());
  await loaded(100);
  await hold(600);
  await tabTo('SLA');
  await loaded(100);
  await moveTo(page, 1000, 560);
  await hold(1500);
  await tabTo('Workload');
  await loaded(100);
  await moveTo(page, 1000, 560);
  await hold(1700);
}

// ~10 s: the Customer Portal: an AI finding from the overview, then the service levels.
async function clipPortal({page, hold, loaded, tabTo}) {
  await hold(1300);
  await moveTo(page, 700, 620);
  await hold(300);
  await glide(page, page.getByRole('button', {name: /view details/i}).first());
  await loaded(200);
  await hold(300);
  await tabTo('AI Report');
  await loaded(200);
  await moveTo(page, 900, 560);
  await hold(2000);
  await page.keyboard.press('Escape');
  await hold(400);
  await glide(page, page.getByText('Service Levels', {exact: true}).first());
  await loaded(200);
  await moveTo(page, 900, 500);
  await hold(2000);
}

const RECORDINGS = {
  tour: () => record('tour', `${APP_URL}/incident-management/alerts`, tour),
  'gif-triage': () => record('gif-triage', `${APP_URL}/incident-management/alerts`, clipTriage),
  'gif-soc': () => record('gif-soc', `${APP_URL}/soc-management`, clipSoc),
  'gif-portal': () => record('gif-portal', `${PORTAL_URL}/overview`, clipPortal),
};

if (RECORD) {
  // gif-triage changes the alert it plays with: record it last, and re-seed afterwards.
  const names = RECORD === 'all' ? ['tour', 'gif-soc', 'gif-portal', 'gif-triage'] : RECORD.split(',');
  for (const name of names) await RECORDINGS[name]();
} else {
  await stills();
}
