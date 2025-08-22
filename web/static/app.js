function badge(status){
  const m = { 
    found: 'badge badge-found', 
    running: 'badge badge-run', 
    done: 'badge badge-done', 
    queued: 'badge badge-queued', 
    error: 'badge badge-error',
    paused: 'badge badge-paused',
    stopped: 'badge badge-stopped'
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
    } else if (t.status === 'paused' && t.progress) {
      const p = t.progress;
      const percent = p.progress_percent ? Math.min(p.progress_percent, 100).toFixed(1) + '%' : '';
      progress = `<div class="progress-info paused">
        <div class="progress-bar-container">
          <div class="progress-bar paused" style="width: ${Math.min(p.progress_percent || 0, 100)}%"></div>
          <span class="progress-text">${formatNumber(tried)}${p.total ? ` / ${formatNumber(p.total)}` : ''}</span>
        </div>
        <small class="muted"><i class="fas fa-pause-circle"></i> Paused at ${percent}</small>
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
    
    // Add resume indicator if task was resumed
    const resumeIndicator = (t.is_paused || t.last_checkpoint) ? 
      `<span class="resume-indicator" title="This task can be resumed"><i class="fas fa-save"></i></span>` : '';
    
    // Generate action buttons based on status
    let actions = '';
    if (t.status === 'running') {
      actions = `
        <button class="btn-small btn-warning" onclick="pauseTask('${t.id}')" title="Pause task">
          <i class="fas fa-pause"></i>
        </button>
        <button class="btn-small btn-secondary" onclick="stopTask('${t.id}')" title="Stop task">
          <i class="fas fa-stop"></i>
        </button>
      `;
    } else if (t.status === 'paused') {
      actions = `
        <button class="btn-small btn-success" onclick="resumeTask('${t.id}')" title="Resume task">
          <i class="fas fa-play"></i>
        </button>
        <button class="btn-small btn-secondary" onclick="deleteTask('${t.id}')" title="Delete task">
          <i class="fas fa-trash"></i>
        </button>
      `;
    } else {
      actions = `
        <button class="btn-small btn-secondary" onclick="deleteTask('${t.id}')" title="Delete task">
          <i class="fas fa-trash"></i>
        </button>
      `;
    }
    
    tr.innerHTML = `
      <td><code>${t.id||''}</code> ${resumeIndicator}</td>
      <td>
        ${algoDisplay}
        <div class="mode-info">${modeInfo}</div>
      </td>
      <td>${badge(t.status)}</td>
      <td class="progress-column">${progress}</td>
      <td>${result}</td>
      <td>
        <div class="task-actions">
          ${actions}
        </div>
      </td>
    `;
    next.push(tr);
  }
  
  tbody.replaceChildren(...next);
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
  submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> creating task...';
  submitBtn.disabled = true;
  
  try {
    const payload = collectFormData(form);
    
    if (!payload || !validatePayload(payload)) {
      return;
    }
    
    const res = await fetch('/api/tasks', {
      method:'POST', 
      headers:{'Content-Type':'application/json'}, 
      body: JSON.stringify(payload)
    });
    
    if (!res.ok){ 
      const txt = await res.text(); 
      showToast('error creating task: ' + txt, 'error'); 
      return; 
    }
    
    showToast('task created successfully!', 'success');
    form.reset();
    showStep(1);
    
    const uploadPlaceholder = document.getElementById('uploadPlaceholder');
    const uploadControls = document.getElementById('uploadControls');
    const uploadSection = document.getElementById('uploadSection');
    if (uploadPlaceholder) uploadPlaceholder.style.display = 'block';
    if (uploadControls) uploadControls.style.display = 'none';
    if (uploadSection) uploadSection.style.display = 'none';
    
    const defaultRadio = document.querySelector('input[name="wordlist_source"][value="default"]');
    if (defaultRadio) {
      defaultRadio.checked = true;
      defaultRadio.dispatchEvent(new Event('change'));
    }
    
    loadTasks();
    
  } catch (error) {
    showToast('failed to create task: ' + error.message, 'error');
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
  const wordlistInput = document.getElementById('wordlist');
  
  if (wordlistSource === 'default') {
    payload.use_default_wordlist = true;
    payload.wordlist = '';
  } else if (wordlistSource === 'upload') {
    payload.use_default_wordlist = false;
    
    let wordlistPath = '';
    if (wordlistInput && wordlistInput.value.trim()) {
      wordlistPath = wordlistInput.value.trim();
    } else if (window.uploadState?.isFileUploaded && window.uploadState.uploadedFilePath) {
      wordlistPath = window.uploadState.uploadedFilePath;
      if (wordlistInput) wordlistInput.value = wordlistPath;
    }
    
    if (!wordlistPath) {
      showToast('please upload a wordlist file first', 'error');
      return null;
    }
    
    payload.wordlist = wordlistPath;
  } else if (payload.mode === 'wordlist') {
    payload.use_default_wordlist = true;
    payload.wordlist = '';
  }
  
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
    showToast('please enter a target hash', 'error');
    showStep(1);
    return false;
  }
  
  if (!payload.algo || payload.algo === 'auto') {
    showToast('please select the algorithm', 'error');
    showStep(1);
    return false;
  }
  
  if (payload.mode === 'wordlist') {
    if (payload.use_default_wordlist) {
      if (payload.wordlist && payload.wordlist.trim() !== '') {
        showToast('choose either default wordlist or custom upload, not both', 'error');
        showStep(2);
        return false;
      }
    } else {
      const hasWordlistPath = payload.wordlist && payload.wordlist.trim() !== '';
      const hasUploadState = window.uploadState && window.uploadState.isFileUploaded;
      
      if (!hasWordlistPath) {
        if (hasUploadState && window.uploadState.uploadedFilePath) {
          payload.wordlist = window.uploadState.uploadedFilePath;
        } else {
          showToast('please upload a wordlist file', 'error');
          showStep(2);
          return false;
        }
      }
    }
  }
  
  if (payload.mode === 'mask' && (!payload.mask || payload.mask.trim() === '')) {
    showToast('please provide a mask pattern', 'error');
    showStep(2);
    return false;
  }
  
  if (payload.mode === 'bruteforce') {
    if (!payload.bf_chars || payload.bf_chars.trim() === '') {
      showToast('please specify character set for brute force', 'error');
      showStep(2);
      return false;
    }
    
    if (payload.bf_min <= 0 || payload.bf_max <= 0 || payload.bf_min > payload.bf_max) {
      showToast('please specify valid length range', 'error');
      showStep(2);
      return false;
    }
  }
  
  return true;
}

// New pause/resume functions
async function pauseTask(taskId) {
  try {
    const res = await fetch(`/api/tasks/${taskId}/pause`, { method: 'POST' });
    if (res.ok) {
      showToast('Task paused. State saved for resumption.', 'success');
      // Optimistic UI: update badge immediately to reduce flicker
      const row = document.querySelector(`#tasks tbody tr[data-id="${taskId}"]`);
      if (row) {
        const statusCell = row.children[2];
        if (statusCell) statusCell.innerHTML = badge('paused');
        // Disable action buttons briefly
        const buttons = row.querySelectorAll('.task-actions button');
        buttons.forEach(b => b.disabled = true);
        setTimeout(() => buttons.forEach(b => b.disabled = false), 600);
      }
      loadTasks();
    } else {
      const error = await res.text();
      showToast('Failed to pause task: ' + error, 'error');
    }
  } catch (error) {
    showToast('Error pausing task: ' + error.message, 'error');
  }
}

async function resumeTask(taskId) {
  try {
    const res = await fetch(`/api/tasks/${taskId}/resume`, { method: 'POST' });
    if (res.ok) {
      showToast('Task resumed from saved state.', 'success');
      const row = document.querySelector(`#tasks tbody tr[data-id="${taskId}"]`);
      if (row) {
        const statusCell = row.children[2];
        if (statusCell) statusCell.innerHTML = badge('running');
        const buttons = row.querySelectorAll('.task-actions button');
        buttons.forEach(b => b.disabled = true);
        setTimeout(() => buttons.forEach(b => b.disabled = false), 600);
      }
      loadTasks();
    } else {
      const error = await res.text();
      showToast('Failed to resume task: ' + error, 'error');
    }
  } catch (error) {
    showToast('Error resuming task: ' + error.message, 'error');
  }
}

async function stopTask(taskId) {
  try {
    const res = await fetch(`/api/tasks/${taskId}/stop`, { method: 'POST' });
    if (res.ok) {
      showToast('Task stopped', 'success');
      // Optimistic UI update to reduce status flicker
      const row = document.querySelector(`#tasks tbody tr[data-id="${taskId}"]`);
      if (row) {
        const statusCell = row.children[2];
        if (statusCell) statusCell.innerHTML = badge('stopped');
        // Disable action buttons briefly to avoid rapid re-clicks
        const buttons = row.querySelectorAll('.task-actions button');
        buttons.forEach(b => b.disabled = true);
        setTimeout(() => buttons.forEach(b => b.disabled = false), 600);
      }
      loadTasks();
    } else {
      showToast('Failed to stop task', 'error');
    }
  } catch (error) {
    showToast('Error stopping task: ' + error.message, 'error');
  }
}

async function deleteTask(taskId) {
  if (!confirm('Are you sure you want to delete this task? This will also delete any saved state.')) {
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
  const fileInput = document.getElementById('uploadFile');
  const uploadPlaceholder = document.getElementById('uploadPlaceholder');
  const uploadControls = document.getElementById('uploadControls');
  const uploadFilename = document.getElementById('uploadFilename');
  
  if (!window.uploadState) {
    window.uploadState = {
      isFileUploaded: false,
      uploadedFilePath: ''
    };
  }
  
  if (fileInput) {
    fileInput.addEventListener('change', async function() {
      if (this.files.length === 0) return;
      
      const file = this.files[0];
      
      if (file.size > 10 * 1024 * 1024) {
        showToast('File too large (max 10MB)', 'error');
        this.value = '';
        return;
      }
      
      const ext = file.name.toLowerCase().split('.').pop();
      if (ext !== 'txt' && ext !== 'lst') {
        showToast('Only .txt and .lst files are supported', 'error');
        this.value = '';
        return;
      }
      
      if (uploadPlaceholder) uploadPlaceholder.style.display = 'none';
      if (uploadControls) uploadControls.style.display = 'flex';
      if (uploadFilename) {
        uploadFilename.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Uploading ${file.name}...`;
      }
      
      window.uploadState.isFileUploaded = false;
      window.uploadState.uploadedFilePath = '';
      const wordlistInput = document.getElementById('wordlist');
      if (wordlistInput) wordlistInput.value = '';
      
      try {
        const form = new FormData();
        form.append('file', file, file.name);
        
        const res = await fetch('/api/uploads', { 
          method: 'POST', 
          body: form 
        });
        
        if (!res.ok) { 
          const errorText = await res.text();
          showToast('Upload failed: ' + errorText, 'error');
          resetUploadUI();
          return;
        }
        
        const data = await res.json();
        
        window.uploadState.isFileUploaded = true;
        window.uploadState.uploadedFilePath = data.path;
        
        if (wordlistInput) {
          wordlistInput.value = data.path;
          wordlistInput.dispatchEvent(new Event('change'));
        }
        
        const useDefaultInput = document.getElementById('useDefault');
        if (useDefaultInput) useDefaultInput.value = 'false';
        
        const uploadRadio = document.querySelector('input[name="wordlist_source"][value="upload"]');
        if (uploadRadio) {
          uploadRadio.checked = true;
          uploadRadio.dispatchEvent(new Event('change'));
        }
        
        if (uploadFilename) {
          uploadFilename.innerHTML = `<i class="fas fa-check-circle" style="color: var(--success-color);"></i> ${file.name} uploaded`;
        }
        
        showToast(`File uploaded: ${data.filename}`, 'success');
        
      } catch (error) {
        showToast('Upload failed: ' + error.message, 'error');
        resetUploadUI();
        window.uploadState.isFileUploaded = false;
        window.uploadState.uploadedFilePath = '';
        if (wordlistInput) wordlistInput.value = '';
      }
    });
  }
  
  function resetUploadUI() {
    if (uploadPlaceholder) uploadPlaceholder.style.display = 'block';
    if (uploadControls) uploadControls.style.display = 'none';
    if (fileInput) fileInput.value = '';
  }
});

let lastStatsUpdate = 0;
let lastTasksUpdate = 0;
const STATS_MIN_INTERVAL = 3000;
const TASKS_MIN_INTERVAL = 1500;

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
  
  // Check for saved tasks on load
  loadTasks().then(() => {
    const tasks = document.querySelectorAll('#tasks tbody tr');
    if (tasks.length > 0) {
      let hasPausedTasks = false;
      tasks.forEach(tr => {
        const statusBadge = tr.querySelector('.badge');
        if (statusBadge && statusBadge.textContent.toLowerCase() === 'paused') {
          hasPausedTasks = true;
        }
      });
      
      if (hasPausedTasks) {
        showToast('Found paused tasks from previous session. Click play to resume.', 'info');
      }
    }
  });
  
  Promise.all([
    loadTasks().catch(err => console.error('Initial tasks load failed:', err)),
    loadStats().catch(err => console.error('Initial stats load failed:', err))
  ]).then(() => {
    // Prefer SSE stream for tasks when available
    try {
      const es = new EventSource('/api/tasks/stream');
      es.addEventListener('tasks', ev => {
        try {
          const data = JSON.parse(ev.data);
          if (window.renderTasks) window.renderTasks(data);
        } catch(e){}
      });
      es.onerror = () => {
        // Fallback to polling if SSE fails
        es.close();
        setInterval(() => {
          loadTasks().catch(err => console.error('Periodic tasks load failed:', err));
        }, 2500);
      };
    } catch (e) {
      setInterval(() => {
        loadTasks().catch(err => console.error('Periodic tasks load failed:', err));
      }, 2500);
    }
    
    setInterval(() => {
      loadStats().catch(err => console.error('Periodic stats load failed:', err));
    }, 5000);
  });
});

// Export functions to global scope
window.pauseTask = pauseTask;
window.resumeTask = resumeTask;
window.stopTask = stopTask;
window.deleteTask = deleteTask;
window.showToast = showToast;
window.showStep = showStep;