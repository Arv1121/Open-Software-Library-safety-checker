/* ============================================================
   Library Safety Checker – Main JS
   ============================================================ */

'use strict';

/* ── Theme ────────────────────────────────────────────────── */
const ThemeManager = (() => {
  const KEY = 'lsc-theme';
  const btn = document.getElementById('theme-toggle');

  function apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(KEY, theme);
    if (btn) btn.textContent = theme === 'dark' ? '☀️' : '🌙';
  }

  function init() {
    const saved = localStorage.getItem(KEY) ||
      (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    apply(saved);
    if (btn) btn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      apply(current === 'dark' ? 'light' : 'dark');
    });
  }

  return { init, apply };
})();

/* ── Toast notifications ──────────────────────────────────── */
const Toast = (() => {
  let container = document.getElementById('toast-container');

  function ensure() {
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      document.body.appendChild(container);
    }
  }

  function show(message, type = 'info') {
    ensure();
    const el = document.createElement('div');
    el.className = 'toast';
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    el.textContent = `${icons[type] || ''} ${message}`;
    container.appendChild(el);
    setTimeout(() => el.remove(), 3100);
  }

  return { show };
})();

/* ── Local storage helpers ────────────────────────────────── */
const Store = {
  get(key, fallback = []) {
    try { return JSON.parse(localStorage.getItem(key)) ?? fallback; }
    catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch {}
  },
};

/* ── Favorites ────────────────────────────────────────────── */
const Favorites = (() => {
  const KEY = 'lsc-favorites';

  function getAll() { return Store.get(KEY, []); }

  function toggle(pkg) {
    let favs = getAll();
    if (favs.includes(pkg)) {
      favs = favs.filter(f => f !== pkg);
      Toast.show(`Removed ${pkg} from favorites`, 'info');
    } else {
      favs.push(pkg);
      Toast.show(`Added ${pkg} to favorites ⭐`, 'success');
    }
    Store.set(KEY, favs);
    refreshButtons(pkg);
    return favs.includes(pkg);
  }

  function isFav(pkg) { return getAll().includes(pkg); }

  function refreshButtons(pkg) {
    document.querySelectorAll(`.fav-btn[data-pkg="${pkg}"]`).forEach(btn => {
      btn.classList.toggle('active', isFav(pkg));
      btn.title = isFav(pkg) ? 'Remove from favorites' : 'Add to favorites';
    });
  }

  function initButtons() {
    document.querySelectorAll('.fav-btn').forEach(btn => {
      const pkg = btn.dataset.pkg;
      btn.classList.toggle('active', isFav(pkg));
      btn.addEventListener('click', () => toggle(pkg));
    });
  }

  return { getAll, toggle, isFav, initButtons };
})();

/* ── Recent searches ──────────────────────────────────────── */
const RecentSearches = (() => {
  const KEY = 'lsc-recent';

  function add(pkg) {
    let recent = Store.get(KEY, []);
    recent = recent.filter(r => r !== pkg);
    recent.unshift(pkg);
    Store.set(KEY, recent.slice(0, 10));
  }

  function getAll() { return Store.get(KEY, []); }

  function render(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const recent = getAll();
    if (!recent.length) {
      el.innerHTML = '<p class="text-slate-400 col-span-full text-sm">No recent searches yet</p>';
      return;
    }
    el.innerHTML = recent.slice(0, 8).map(pkg => `
      <button onclick="submitSearch('${pkg}')"
        class="glass hover-lift rounded-lg px-3 py-2 text-sm text-left hover:border-blue-500 transition flex items-center gap-2">
        <span class="text-slate-400">🕐</span>
        <span class="truncate">${pkg}</span>
      </button>`).join('');
  }

  return { add, getAll, render };
})();

/* ── Autocomplete ─────────────────────────────────────────── */
const Autocomplete = (() => {
  let activeIdx = -1;
  let items = [];

  function init(inputId, listId) {
    const input = document.getElementById(inputId);
    const list  = document.getElementById(listId);
    if (!input || !list) return;

    let debounceTimer;

    input.addEventListener('input', () => {
      clearTimeout(debounceTimer);
      const q = input.value.trim();
      if (q.length < 1) { hide(list); return; }
      debounceTimer = setTimeout(() => fetchSuggestions(q, input, list), 180);
    });

    input.addEventListener('keydown', e => {
      if (!list.children.length) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); moveFocus(list, 1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); moveFocus(list, -1); }
      else if (e.key === 'Enter' && activeIdx >= 0) {
        e.preventDefault();
        input.value = items[activeIdx];
        hide(list);
        activeIdx = -1;
      } else if (e.key === 'Escape') { hide(list); }
    });

    document.addEventListener('click', e => {
      if (!input.contains(e.target) && !list.contains(e.target)) hide(list);
    });
  }

  function fetchSuggestions(q, input, list) {
    fetch(`/api/autocomplete?q=${encodeURIComponent(q)}`)
      .then(r => r.json())
      .then(data => {
        items = data;
        activeIdx = -1;
        if (!data.length) { hide(list); return; }
        list.innerHTML = data.map((pkg, i) =>
          `<li data-idx="${i}" class="flex items-center gap-2">
             <span class="text-slate-400 text-xs">📦</span>
             <span>${highlight(pkg, q)}</span>
           </li>`
        ).join('');
        list.classList.remove('hidden');
        list.querySelectorAll('li').forEach(li => {
          li.addEventListener('mousedown', e => {
            e.preventDefault();
            input.value = items[+li.dataset.idx];
            hide(list);
          });
        });
      })
      .catch(() => hide(list));
  }

  function moveFocus(list, dir) {
    const lis = list.querySelectorAll('li');
    if (!lis.length) return;
    lis[activeIdx]?.classList.remove('active');
    activeIdx = (activeIdx + dir + lis.length) % lis.length;
    lis[activeIdx].classList.add('active');
    lis[activeIdx].scrollIntoView({ block: 'nearest' });
  }

  function hide(list) { list.classList.add('hidden'); list.innerHTML = ''; }

  function highlight(text, q) {
    const idx = text.toLowerCase().indexOf(q.toLowerCase());
    if (idx < 0) return text;
    return text.slice(0, idx) +
      `<strong class="text-blue-400">${text.slice(idx, idx + q.length)}</strong>` +
      text.slice(idx + q.length);
  }

  return { init };
})();

/* ── Search form helper ───────────────────────────────────── */
function submitSearch(pkg) {
  const form = document.getElementById('search-form');
  const input = document.getElementById('pkg-input');
  if (!form || !input) return;
  input.value = pkg;
  form.submit();
}

/* ── Export helpers ───────────────────────────────────────── */
function exportJSON(pkg) {
  window.location.href = `/api/export/json/${encodeURIComponent(pkg)}`;
  Toast.show('Downloading JSON report…', 'info');
}

function exportPDF() {
  Toast.show('Preparing PDF…', 'info');
  window.print();
}

/* ── Vulnerability chart (Chart.js) ──────────────────────── */
function renderVulnChart(canvasId, counts) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || typeof Chart === 'undefined') return;

  const labels = ['Critical', 'High', 'Medium', 'Low'];
  const data   = [counts.CRITICAL || 0, counts.HIGH || 0, counts.MEDIUM || 0, counts.LOW || 0];
  const colors = ['#ef4444', '#f59e0b', '#3b82f6', '#10b981'];

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }]
    },
    options: {
      cutout: '70%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#94a3b8', padding: 16, font: { size: 12 } }
        },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed}`
          }
        }
      }
    }
  });
}

/* ── Dashboard filter / sort ──────────────────────────────── */
const DashboardFilter = (() => {
  let currentFilter = 'all';
  let currentSort   = 'name';

  function init() {
    document.querySelectorAll('.filter-chip[data-filter]').forEach(chip => {
      chip.addEventListener('click', () => {
        document.querySelectorAll('.filter-chip[data-filter]').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        currentFilter = chip.dataset.filter;
        applyFilterSort();
      });
    });

    const sortSel = document.getElementById('sort-select');
    if (sortSel) sortSel.addEventListener('change', () => {
      currentSort = sortSel.value;
      applyFilterSort();
    });
  }

  function applyFilterSort() {
    const cards = Array.from(document.querySelectorAll('.pkg-card'));

    cards.forEach(card => {
      const verdict = (card.dataset.verdict || '').toLowerCase();
      const show = currentFilter === 'all' ||
        (currentFilter === 'safe'   && verdict === 'safe') ||
        (currentFilter === 'review' && verdict === 'needs review') ||
        (currentFilter === 'unsafe' && verdict === 'unsafe');
      card.style.display = show ? '' : 'none';
    });

    const grid = document.getElementById('pkg-grid');
    if (!grid) return;
    const visible = cards.filter(c => c.style.display !== 'none');
    visible.sort((a, b) => {
      if (currentSort === 'name')   return a.dataset.name.localeCompare(b.dataset.name);
      if (currentSort === 'vulns')  return (+b.dataset.vulns)  - (+a.dataset.vulns);
      if (currentSort === 'verdict') return a.dataset.verdict.localeCompare(b.dataset.verdict);
      return 0;
    });
    visible.forEach(c => grid.appendChild(c));
  }

  return { init };
})();

/* ── Comparison builder ───────────────────────────────────── */
const CompareBuilder = (() => {
  const KEY = 'lsc-compare-queue';

  function getQueue() { return Store.get(KEY, []); }

  function add(pkg) {
    let q = getQueue();
    if (q.includes(pkg)) { Toast.show(`${pkg} already in comparison`, 'warning'); return; }
    if (q.length >= 3)   { Toast.show('Max 3 packages for comparison', 'warning'); return; }
    q.push(pkg);
    Store.set(KEY, q);
    Toast.show(`Added ${pkg} to comparison`, 'success');
    refreshBadge();
  }

  function clear() { Store.set(KEY, []); refreshBadge(); }

  function goCompare() {
    const q = getQueue();
    if (q.length < 2) { Toast.show('Add at least 2 packages to compare', 'warning'); return; }
    window.location.href = '/compare?' + q.map(p => `pkg=${encodeURIComponent(p)}`).join('&');
  }

  function refreshBadge() {
    const badge = document.getElementById('compare-badge');
    const q = getQueue();
    if (badge) {
      badge.textContent = q.length;
      badge.style.display = q.length ? 'flex' : 'none';
    }
  }

  function init() {
    refreshBadge();
    document.querySelectorAll('.compare-add-btn').forEach(btn => {
      btn.addEventListener('click', () => add(btn.dataset.pkg));
    });
    const goBtn = document.getElementById('go-compare-btn');
    if (goBtn) goBtn.addEventListener('click', goCompare);
    const clearBtn = document.getElementById('clear-compare-btn');
    if (clearBtn) clearBtn.addEventListener('click', () => { clear(); Toast.show('Comparison cleared', 'info'); });
  }

  return { init, add, clear, goCompare };
})();

/* ── Trending widget ──────────────────────────────────────── */
function loadTrendingWidget(containerId) {
  const el = document.getElementById(containerId);
  if (!el) return;
  fetch('/api/trending')
    .then(r => r.json())
    .then(data => {
      if (!data.length) {
        el.innerHTML = '<p class="text-slate-400 text-sm">No trending data yet</p>';
        return;
      }
      el.innerHTML = data.map((item, i) => `
        <div class="flex items-center justify-between py-2 border-b border-slate-700/50 last:border-0">
          <div class="flex items-center gap-2">
            <span class="text-slate-500 text-xs w-4">${i + 1}</span>
            <button onclick="submitSearch('${item.package}')"
              class="text-sm font-medium hover:text-blue-400 transition">${item.package}</button>
          </div>
          <span class="trending-badge">🔥 ${item.count}</span>
        </div>`).join('');
    })
    .catch(() => { el.innerHTML = '<p class="text-slate-400 text-sm">Unable to load trending</p>'; });
}

/* ── Init ─────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  ThemeManager.init();
  Favorites.initButtons();
  Autocomplete.init('pkg-input', 'autocomplete-list');
  DashboardFilter.init();
  CompareBuilder.init();

  // Render recent searches widget
  RecentSearches.render('recent-searches');

  // Save search on form submit
  const form = document.getElementById('search-form');
  if (form) {
    form.addEventListener('submit', () => {
      const input = document.getElementById('pkg-input');
      if (input && input.value.trim()) RecentSearches.add(input.value.trim());
    });
  }

  // Animate counters
  document.querySelectorAll('[data-count]').forEach(el => {
    const target = parseInt(el.dataset.count, 10);
    if (isNaN(target)) return;
    let current = 0;
    const step = Math.max(1, Math.ceil(target / 40));
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      el.textContent = current.toLocaleString();
      if (current >= target) clearInterval(timer);
    }, 30);
  });
});
