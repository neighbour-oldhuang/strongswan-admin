// auto-refresh status every 8s
async function refreshStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    const el = document.getElementById('svc-status');
    if (el) {
      el.className = 'badge ' + (d.active ? 'badge-green' : 'badge-red');
      el.textContent = d.active ? '运行中' : '已停止';
    }
  } catch {}
}

async function refreshLogs() {
  try {
    const r = await fetch('/api/logs');
    const d = await r.json();
    const el = document.getElementById('logbox');
    if (el) { el.textContent = d.logs; el.scrollTop = el.scrollHeight; }
  } catch {}
}

document.addEventListener('DOMContentLoaded', () => {
  // PSK 生成按钮
  const btnPsk = document.getElementById('btn-gen-psk');
  if (btnPsk) {
    btnPsk.addEventListener('click', async () => {
      const r = await fetch('/api/gen-psk');
      const d = await r.json();
      document.getElementById('field-psk').value = d.psk;
    });
  }
  document.querySelectorAll('[data-confirm]').forEach(btn => {
    btn.addEventListener('click', e => {
      if (!confirm(btn.dataset.confirm)) e.preventDefault();
    });
  });
});
