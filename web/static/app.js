function badge(status){
  const m = { 
    found: 'badge badge-found', 
    running: 'badge badge-run', 
    done: 'badge badge-done', 
    queued: 'badge badge-queued', 
    error: 'badge badge-error'
  };
  return `<span class="${m[status]||'badge'}">${status}</span>`;
}

window.renderTasks = function(tasks){
  const tbody = document.querySelector('#tasks tbody');
  if (!tbody) return;
  
  const existing = new Map(Array.from(tbody.children).map(tr => [tr.dataset.id, tr]));
  const next = [];
  
  for (const t of tasks){
    let tr = existing.get(t.id);
    if (!tr){ 
      tr = document.createElement('tr'); 
      tr.dataset.id = t.id; 
    }
    
    const tried = t.result?.tried ?? t.progress?.tried ?? '';
    const durMs = t.result ? Math.round((t.result.duration_ns||0)/1e6) : '';
    const result = t.result?.plaintext ? `<strong style="color: var(--success-color);">${escapeHtml(t.result.plaintext)}</strong>` : '';
    
    // ugly progress bar, todo: nuke this and make a proper one.
    let progress = '';
    if (t.status === 'running' && t.progress) {
      const p = t.progress;
      const speed = p.attempts_per_second ? formatSpeed(p.attempts_per_second) : '';
      const eta = p.eta_seconds ? formatDuration(p.eta_seconds) : '';
      const percent = p.progress_percent ? Math.min(p.progress_percent, 100).toFixed(1) + '%' : '';
      const currentInfo = p.current_candidate ? `${escapeHtml(p.current_candidate.substring(0, 8))}${p.current_candidate.length > 8 ? '...' : ''}` : '';
      const lengthInfo = p.current_length ? `L:${p.current_length}` : '';
      const memInfo = p.memory_mb ? `${p.memory_mb.toFixed(0)}MB` : '';
      
      progress = `<div class="progress-info enhanced">
        <div class="progress-main">
          <div class="progress-bar-container">
            <div class="progress-bar" style="width: ${Math.min(p.progress_percent || 0, 100)}%"></div>
            <span class="progress-text">${formatNumber(tried)}${p.total ? ` / ${formatNumber(p.total)}` : ''}</span>
          </div>
          <div class="progress-metrics">
            ${percent ? `<span class="metric"><i class="fas fa-percentage"></i> ${percent}</span>` : ''}
            ${speed ? `<span class="metric"><i class="fas fa-tachometer-alt"></i> ${speed}</span>` : ''}
            ${eta ? `<span class="metric"><i class="fas fa-clock"></i> ${eta}</span>` : ''}
          </div>
        </div>
        <div class="progress-details">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            ${currentInfo ? `<div class="current-candidate" title="Current: ${escapeHtml(p.current_candidate)}">${currentInfo}</div>` : ''}
            <div style="display: flex; gap: 8px; font-size: 0.6rem;">
              ${lengthInfo ? `<span class="length-info">${lengthInfo}</span>` : ''}
              ${memInfo ? `<span class="mem-info" title="Memory usage">${memInfo}</span>` : ''}
            </div>
          </div>
        </div>
      </div>`;
    } else if (t.status === 'running' && tried) {
      progress = `<div class="progress-info basic">
        <div class="progress-spinner">
          <i class="fas fa-spinner fa-spin"></i>
        </div>
        <small class="muted">${formatNumber(tried)} attempts</small>
      </div>`;
    } else if (tried) {
      const duration = durMs ? ` (${formatTime(durMs)})` : '';
      progress = `<small class="muted">${formatNumber(tried)} attempts${duration}</small>`;
    }
    
    const algoDisplay = t.algo + (t.detected && t.detected.length ? 
      ` <small class="muted" title="Auto-detected from: ${t.detected.join(', ')}">(detected)</small>` : '');
    
    const modeInfo = getModeInfo(t);
    
    tr.innerHTML = `
      <td><code>${t.id||''}</code></td>
      <td>
        ${algoDisplay}
        <div class="mode-info">${modeInfo}</div>
      </td>
      <td>${badge(t.status)}</td>
      <td class="progress-column">${progress}</td>
      <td>${result}</td>
      <td>
        <div class="task-actions">
          ${t.status === 'running' ? 
            '<button class="btn-small btn-secondary" onclick="stopTask(\'' + t.id + '\')"><i class="fas fa-stop"></i></button>' : 
            '<button class="btn-small btn-secondary" onclick="deleteTask(\'' + t.id + '\')"><i class="fas fa-trash"></i></button>'
          }
        </div>
      </td>
    `;
    next.push(tr);
  }
  
  // Replace tbody children in one pass to prevent flicker
  tbody.replaceChildren(...next);
  
  // Update tasks visibility
  updateTasksVisibility(tasks.length > 0);
}

function updateTasksVisibility(hasTasks) {
  const noTasks = document.getElementById('no-tasks');
  const tasksContainer = document.getElementById('tasksContainer');
  
  if (noTasks && tasksContainer) {
    if (hasTasks) {
      noTasks.style.display = 'none';
      tasksContainer.style.display = 'block';
    } else {
      noTasks.style.display = 'flex';
      tasksContainer.style.display = 'none';
    }
  }
}

function getModeInfo(task) {
  const mode = task.mode || 'wordlist';
  switch (mode) {
    case 'mask':
      return `<small class="mode-badge mode-mask"><i class="fas fa-mask"></i> Mask: ${task.mask || '?'}</small>`;
    case 'bruteforce':
      return `<small class="mode-badge mode-bruteforce"><i class="fas fa-bolt"></i> Brute ${task.bf_min}-${task.bf_max} chars</small>`;
    case 'wordlist':
    default:
      const source = task.use_default_wordlist ? 'default' : (task.wordlist ? 'custom' : 'none');
      return `<small class="mode-badge mode-wordlist"><i class="fas fa-list"></i> Wordlist (${source})</small>`;
  }
}

function formatNumber(num) {
  if (!num || !isFinite(num) || isNaN(num)) return '0';
  const numVal = Number(num);
  if (numVal < 1000) return Math.round(numVal).toString();
  if (numVal < 1000000) return (numVal / 1000).toFixed(1) + 'K';
  if (numVal < 1000000000) return (numVal / 1000000).toFixed(1) + 'M';
  if (numVal < 1000000000000) return (numVal / 1000000000).toFixed(1) + 'B';
  return (numVal / 1000000000000).toFixed(1) + 'T';
}

function formatSpeed(speed) {
  if (!speed || speed <= 0 || !isFinite(speed)) return '';
  
  const numSpeed = Number(speed);
  if (!isFinite(numSpeed) || isNaN(numSpeed)) return '';
  
  if (numSpeed < 1000) return `${Math.round(numSpeed)} h/s`;
  if (numSpeed < 1000000) return `${(numSpeed / 1000).toFixed(1)}K h/s`;
  if (numSpeed < 1000000000) return `${(numSpeed / 1000000).toFixed(1)}M h/s`;
  return `${(numSpeed / 1000000000).toFixed(1)}G h/s`;
}

function formatTime(ms) {
  if (!ms) return '';
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${minutes}m${secs > 0 ? ` ${secs}s` : ''}`;
}

function formatDuration(seconds) {
  if (!seconds || seconds <= 0) return '';
  
  if (seconds < 60) {
    return `${Math.round(seconds)}s`;
  } else if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
  } else if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  } else {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
  }
}

function escapeHtml(s){ 
  return String(s).replace(/[&<>"]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c])); 
}

function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <i class="fas fa-${type === 'error' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
    <span>${message}</span>
  `;
  
  document.body.appendChild(toast);
  
  setTimeout(() => {
    toast.classList.add('show');
  }, 100);
  
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => document.body.removeChild(toast), 300);
  }, 3000);
}

function showStep(step) {
  document.querySelectorAll('.form-step').forEach(s => s.classList.remove('active'));
  const targetStep = document.getElementById(`step${step}`);
  if (targetStep) {
    targetStep.classList.add('active');
  }
}

async function createTask(evt){
  evt.preventDefault();
  const form = evt.target;
  
  const submitBtn = form.querySelector('button[type="submit"]');
  const originalText = submitBtn.innerHTML;
  submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating Task...';
  submitBtn.disabled = true;
  
  try {
    const payload = collectFormData(form);
    
    if (!validatePayload(payload)) {
      return;
    }
    
    const res = await fetch('/api/tasks', {
      method:'POST', 
      headers:{'Content-Type':'application/json'}, 
      body: JSON.stringify(payload)
    });
    
    if (!res.ok){ 
      const txt = await res.text(); 
      showToast('Error creating task: ' + txt, 'error'); 
      return; 
    }
    
    showToast('Task created successfully!', 'success');
    form.reset();
    showStep(1); 
    loadTasks();
    
  } catch (error) {
    showToast('Failed to create task: ' + error.message, 'error');
  } finally {
    submitBtn.innerHTML = originalText;
    submitBtn.disabled = false;
  }
}

function collectFormData(form) {
  const fd = new FormData(form);
  const payload = Object.fromEntries(fd.entries());
  
  payload.workers = Math.max(1, Number(payload.workers||1));
  payload.bf_min = Number(payload.bf_min||0);
  payload.bf_max = Number(payload.bf_max||0);
  
  const wordlistSource = document.querySelector('input[name="wordlist_source"]:checked')?.value;
  payload.use_default_wordlist = wordlistSource === 'default';
  
  payload.rules = Array.from(form.querySelectorAll('input[name="rules"]:checked')).map(el=>el.value);
  
  ['bcrypt_cost', 'scrypt_n', 'scrypt_r', 'scrypt_p', 'argon_time', 'argon_mem_kb', 'argon_par'].forEach(field => {
    if (payload[field]) {
      payload[field] = Number(payload[field]);
    } else {
      delete payload[field];
    }
  });
  
  return payload;
}

function validatePayload(payload) {
  if (!payload.target || !payload.target.trim()) {
    showToast('Please enter a target hash', 'error');
    showStep(1);
    return false;
  }
  if (!payload.algo || payload.algo === 'auto') {
    showToast('Please select the algorithm (auto-detect only provides suggestions).', 'error');
    showStep(1);
    return false;
  }
  
  if (payload.mode === 'wordlist' && payload.use_default_wordlist && (payload.wordlist||'').trim() !== ''){
    showToast('Choose either default wordlist or custom upload, not both.', 'error'); 
    return false;
  }
  
  if (payload.mode === 'mask' && !payload.mask) {
    showToast('Please provide a mask pattern for mask attack', 'error');
    showStep(2);
    return false;
  }
  
  if (payload.mode === 'bruteforce' && !payload.bf_chars) {
    showToast('Please specify character set for brute force attack', 'error');
    showStep(2);
    return false;
  }
  
  return true;
}

document.addEventListener('DOMContentLoaded', function() {
  const uploadBtn = document.getElementById('uploadBtn');
  const fileInput = document.getElementById('uploadFile');
  
  if (uploadBtn && fileInput) {
    uploadBtn.addEventListener('click', async () => {
      if (!fileInput.files.length) { 
        showToast('Please choose a .txt or .lst file', 'error'); 
        return; 
      }
      
      const file = fileInput.files[0];
      if (file.size > 10 * 1024 * 1024) { 
        showToast('File too large (max 10MB)', 'error'); 
        return; 
      }
      
      // Show upload progress
      uploadBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Uploading...';
      uploadBtn.disabled = true;
      
      try {
        const form = new FormData();
        form.append('file', file, file.name);
        
        const res = await fetch('/api/uploads', { method: 'POST', body: form });
        if (!res.ok) { 
          showToast('Upload failed', 'error'); 
          return; 
        }
        
        const data = await res.json();
        
        document.querySelector('input[name="wordlist"]').value = data.path;
        
        const customRadio = document.querySelector('input[name="wordlist_source"][value="upload"]');
        if (customRadio) {
          customRadio.checked = true;
          customRadio.dispatchEvent(new Event('change'));
        }
        
        showToast('File uploaded successfully: ' + data.path, 'success');
        
      } catch (error) {
        showToast('Upload failed: ' + error.message, 'error');
      } finally {
        uploadBtn.innerHTML = '<i class="fas fa-upload"></i> Upload File';
        uploadBtn.disabled = false;
      }
    });
  }
});

let lastStatsUpdate = 0;
let lastTasksUpdate = 0;
const STATS_MIN_INTERVAL = 3000; // min 3 seconds between stats updates
const TASKS_MIN_INTERVAL = 1500; // min 1.5 seconds between task updates

async function loadStats() {
  const now = Date.now();
  if (now - lastStatsUpdate < STATS_MIN_INTERVAL) {
    return;
  }
  lastStatsUpdate = now;
  
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    
    const stats = await res.json();
    
    if (!stats || !stats.system) {
      console.warn('Invalid stats response structure');
      return;
    }
    
    const cpuEl = document.getElementById('cpu-count');
    const goroutinesEl = document.getElementById('goroutines');
    const memoryEl = document.getElementById('memory');
    
    // CPU count
    if (cpuEl) {
      if (typeof stats.system.num_cpu === 'number' && stats.system.num_cpu > 0) {
        cpuEl.textContent = `${stats.system.num_cpu} cores`;
      } else {
        cpuEl.textContent = 'N/A';
      }
    }
    
    if (goroutinesEl) {
      if (typeof stats.system.goroutines === 'number' && stats.system.goroutines >= 0) {
        goroutinesEl.innerHTML = `<span title="Active goroutines">${stats.system.goroutines} routines</span>`;
      } else {
        goroutinesEl.textContent = 'N/A';
      }
    }
    
    if (memoryEl) {
      if (typeof stats.system.alloc_mb === 'number' && !isNaN(stats.system.alloc_mb) && isFinite(stats.system.alloc_mb)) {
        const allocMB = stats.system.alloc_mb.toFixed(1);
        const sysMB = (typeof stats.system.sys_mb === 'number' && !isNaN(stats.system.sys_mb)) ? 
          stats.system.sys_mb.toFixed(1) : '?';
        memoryEl.innerHTML = `<span title="Allocated: ${allocMB}MB, System: ${sysMB}MB">${allocMB}MB</span>`;
      } else {
        memoryEl.textContent = 'N/A';
      }
    }
    
    const taskStatsEl = document.getElementById('task-stats');
    if (taskStatsEl && stats.tasks) {
      const running = stats.tasks.running || 0;
      const total = stats.tasks.total || 0;
      const speed = stats.tasks.total_speed_per_sec || 0;
      const attempts = stats.tasks.total_attempts || 0;
      
      let html = `
        <div class="stat-item">
          <i class="fas fa-tasks"></i>
          <span>${running}/${total} running</span>
        </div>`;
      
      if (speed > 0) {
        html += `
        <div class="stat-item">
          <i class="fas fa-tachometer-alt"></i>
          <span>${formatSpeed(speed)}</span>
        </div>`;
      }
      
      if (attempts > 0) {
        html += `
        <div class="stat-item">
          <i class="fas fa-calculator"></i>
          <span>${formatNumber(attempts)} total</span>
        </div>`;
      }
      
      taskStatsEl.innerHTML = html;
    }
    
  } catch (error) {
    console.error('Failed to load stats:', error);
    const cpuEl = document.getElementById('cpu-count');
    const goroutinesEl = document.getElementById('goroutines');
    const memoryEl = document.getElementById('memory');
    
    if (cpuEl) cpuEl.textContent = 'N/A';
    if (goroutinesEl) goroutinesEl.textContent = 'N/A';
    if (memoryEl) memoryEl.textContent = 'N/A';
  }
}

async function loadTasks(){
  const now = Date.now();
  if (now - lastTasksUpdate < TASKS_MIN_INTERVAL) {
    return; 
  }
  lastTasksUpdate = now;
  
  try{ 
    const r = await fetch('/api/tasks'); 
    const j = await r.json(); 
    if (window.renderTasks) {
      window.renderTasks(j);
    }
  } catch(e) {
    console.error('Failed to load tasks:', e);
  }
}

async function stopTask(taskId) {
  try {
    const res = await fetch(`/api/tasks/${taskId}/stop`, { method: 'POST' });
    if (res.ok) {
      showToast('Task stopped', 'success');
      loadTasks();
    } else {
      showToast('Failed to stop task', 'error');
    }
  } catch (error) {
    showToast('Error stopping task: ' + error.message, 'error');
  }
}

async function deleteTask(taskId) {
  if (!confirm('Are you sure you want to delete this task?')) {
    return;
  }
  
  try {
    const res = await fetch(`/api/tasks/${taskId}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Task deleted', 'success');
      loadTasks();
    } else {
      showToast('Failed to delete task', 'error');
    }
  } catch (error) {
    showToast('Error deleting task: ' + error.message, 'error');
  }
}

document.addEventListener('DOMContentLoaded', function() {
  const taskForm = document.getElementById('taskForm');
  if (taskForm) {
    taskForm.addEventListener('submit', createTask);
  }
  
  const cpuEl = document.getElementById('cpu-count');
  const goroutinesEl = document.getElementById('goroutines');
  const memoryEl = document.getElementById('memory');
  
  if (cpuEl) cpuEl.textContent = 'Loading...';
  if (goroutinesEl) goroutinesEl.textContent = 'Loading...';
  if (memoryEl) memoryEl.textContent = 'Loading...';
  
  Promise.all([
    loadTasks().catch(err => console.error('Initial tasks load failed:', err)),
    loadStats().catch(err => console.error('Initial stats load failed:', err))
  ]).then(() => {
    setInterval(() => {
      loadTasks().catch(err => console.error('Periodic tasks load failed:', err));
    }, 2500);  s
    
    setInterval(() => {
      loadStats().catch(err => console.error('Periodic stats load failed:', err));
    }, 5000); 
  });
});

window.stopTask = stopTask;
window.deleteTask = deleteTask;
window.showToast = showToast;
window.showStep = showStep;
