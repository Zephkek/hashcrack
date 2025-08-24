// Global state
window.uploadState = {
  isFileUploaded: false,
  uploadedFilePath: null,
  uploadedFileName: null
};

async function loadTasks() {
  try {
    const resp = await fetch('/api/tasks');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const tasks = await resp.json();
    renderTasks(tasks);
    return tasks;
  } catch (error) {
    console.error('Failed to load tasks:', error);
    showToast('Failed to load tasks', 'error');
    return [];
  }
}

async function loadSta    tr.innerHTML = `
      <td><code>${t.id||''}</code> ${resumeIndicator}</td>
      <td>
        ${algoDisplay}
        <div class="mode-info">${modeInfo}</div>
      </td>
      <td>${badge(t.status)}</td>
      <td class="progress-column">
        ${progress}
        ${cacheIndicator}
      </td>
      <td>${result}</td>`; try {
    const resp = await fetch('/api/stats');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const stats = await resp.json();
    
    const cpuEl = document.getElementById('cpu-count');
    const goroutinesEl = document.getElementById('goroutines');
    const memoryEl = document.getElementById('memory');
    
    if (cpuEl) cpuEl.textContent = stats.system?.num_cpu || '0';
    if (goroutinesEl) goroutinesEl.textContent = stats.system?.goroutines || '0';
    if (memoryEl) memoryEl.textContent = formatBytes(stats.system?.alloc_bytes || 0);
    
    return stats;
  } catch (error) {
    console.error('Failed to load stats:', error);
    return null;
  }
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

function formatNumber(n) {
  if (typeof n !== 'number') n = Number(n) || 0;
  if (n < 1000) return n.toString();
  if (n < 1000000) return (n / 1000).toFixed(1) + 'K';
  if (n < 1000000000) return (n / 1000000).toFixed(1) + 'M';
  if (n < 1000000000000) return (n / 1000000000).toFixed(1) + 'B';
  return (n / 1000000000000).toFixed(1) + 'T';
}

function formatSpeed(speed) {
  if (!speed || speed === 0) return '0 H/s';
  if (speed < 1000) return speed.toFixed(0) + ' H/s';
  if (speed < 1000000) return (speed / 1000).toFixed(1) + ' KH/s';
  if (speed < 1000000000) return (speed / 1000000).toFixed(1) + ' MH/s';
  if (speed < 1000000000000) return (speed / 1000000000).toFixed(1) + ' GH/s';
  return (speed / 1000000000000).toFixed(1) + ' TH/s';
}

function formatTime(ms) {
  if (ms < 1000) return ms + 'ms';
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return `${m}m ${rs}s`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  if (h < 24) return `${h}h ${rm}m`;
  const d = Math.floor(h / 24);
  const rh = h % 24;
  return `${d}d ${rh}h`;
}

function badge(status) {
  const cls = {
    running: 'badge-primary',
    queued: 'badge-secondary',
    found: 'badge-success',
    stopped: 'badge-secondary',
    done: 'badge-info',
    error: 'badge-error',
    downloading: 'badge-warning',
    paused: 'badge-warning'
  }[status] || 'badge-secondary';
  
  const text = status === 'found' ? 'FOUND ✓' : status.toUpperCase();
  return `<span class="badge ${cls}">${text}</span>`;
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container') || (() => {
    const div = document.createElement('div');
    div.id = 'toast-container';
    document.body.appendChild(div);
    return div;
  })();
  
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <i class="fas fa-${type === 'error' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
    <span>${message}</span>
  `;
  
  container.appendChild(toast);
  setTimeout(() => toast.classList.add('show'), 10);
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

async function createTask(event) {
  event.preventDefault();
  
  const form = event.target;
  const payload = extractFormData(form);
  
  if (!payload) return;
  
  if (!validatePayload(payload)) return;
  
  try {
    const resp = await fetch('/api/tasks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    if (!resp.ok) {
      const errorText = await resp.text();
      throw new Error(errorText || `HTTP ${resp.status}`);
    }
    
    const task = await resp.json();
    showToast('Task created successfully!', 'success');
    
    // Reset form
    form.reset();
    showStep(1);
    
    // Clear uploaded file state
    window.uploadState = {
      isFileUploaded: false,
      uploadedFilePath: null,
      uploadedFileName: null
    };
    updateUploadedFileDisplay();
    
    // Reload tasks
    await loadTasks();
  } catch (error) {
    console.error('Failed to create task:', error);
    showToast(error.message || 'Failed to create task', 'error');
  }
}

function extractFormData(form) {
  const data = new FormData(form);
  const payload = {};
  
  for (const [key, value] of data.entries()) {
    if (value !== '' && value !== null) {
      payload[key] = value;
    }
  }
  
  // Ensure workers is a number
  if (payload.workers) {
    payload.workers = Number(payload.workers) || 4;
  }
  
  // Handle wordlist source
  const wordlistSource = document.querySelector('input[name="wordlist_source"]:checked')?.value || 'default';
  const wordlistInput = document.getElementById('wordlistPath');
  
  if (payload.mode === 'combination') {
    // Handle combination mode with two wordlists
    const wl1Source = document.querySelector('input[name="comb_wl1_source"]:checked')?.value || 'upload';
    const wl2Source = document.querySelector('input[name="comb_wl2_source"]:checked')?.value || 'upload';
    
    // Handle first wordlist
    if (wl1Source === 'upload') {
      if (!payload.wordlist1 || payload.wordlist1.trim() === '') {
        showToast('please upload the first wordlist file for combination attack', 'error');
        return null;
      }
    } else if (wl1Source === 'url') {
      const wl1UrlInput = document.getElementById('combWordlist1Url');
      const wl1Url = wl1UrlInput ? wl1UrlInput.value.trim() : '';
      
      if (!wl1Url) {
        showToast('please enter a URL for the first wordlist', 'error');
        return null;
      }
      
      if (!isValidUrl(wl1Url)) {
        showToast('please enter a valid URL for the first wordlist', 'error');
        return null;
      }
      
      payload.wordlist1_url = wl1Url;
      payload.wordlist1 = '';
    }
    
    // Handle second wordlist
    if (wl2Source === 'upload') {
      if (!payload.wordlist2 || payload.wordlist2.trim() === '') {
        showToast('please upload the second wordlist file for combination attack', 'error');
        return null;
      }
    } else if (wl2Source === 'url') {
      const wl2UrlInput = document.getElementById('combWordlist2Url');
      const wl2Url = wl2UrlInput ? wl2UrlInput.value.trim() : '';
      
      if (!wl2Url) {
        showToast('please enter a URL for the second wordlist', 'error');
        return null;
      }
      
      if (!isValidUrl(wl2Url)) {
        showToast('please enter a valid URL for the second wordlist', 'error');
        return null;
      }
      
      payload.wordlist2_url = wl2Url;
      payload.wordlist2 = '';
    }
    
    payload.use_default_wordlist = false;
  } else if (payload.mode === 'association') {
    // For association attacks, always set to false since it generates its own candidates
    payload.use_default_wordlist = false;
  } else if (wordlistSource === 'default') {
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
  } else if (wordlistSource === 'url') {
    payload.use_default_wordlist = false;
    
    const urlInput = document.getElementById('wordlistUrl');
    const wordlistUrl = urlInput ? urlInput.value.trim() : '';
    
    if (!wordlistUrl) {
      showToast('please enter a wordlist URL', 'error');
      return null;
    }
    
    if (!isValidUrl(wordlistUrl)) {
      showToast('please enter a valid URL', 'error');
      return null;
    }
    
    payload.wordlist_url = wordlistUrl;
    payload.wordlist = ''; // Server will handle URL download
  } else if (payload.mode === 'wordlist') {
    payload.use_default_wordlist = true;
    payload.wordlist = '';
  }
  
  payload.rules = Array.from(form.querySelectorAll('input[name="rules"]:checked')).map(el=>el.value);
  
  // Map HTML form field names to Go struct field names
  if (payload.argon_memory) {
    payload.argon_mem_kb = Number(payload.argon_memory);
    delete payload.argon_memory;
  }
  if (payload.argon_parallelism) {
    payload.argon_par = Number(payload.argon_parallelism);
    delete payload.argon_parallelism;
  }
  
  ['bcrypt_cost', 'scrypt_n', 'scrypt_r', 'scrypt_p', 'argon_time', 'argon_mem_kb', 'argon_par', 'pbkdf2_iterations'].forEach(field => {
    if (payload[field] && payload[field] !== '' && payload[field] !== '0') {
      payload[field] = Number(payload[field]);
    } else {
      delete payload[field];
    }
  });
  
  // Handle hybrid mask - copy hybrid_mask to mask if mode is hybrid and mask is empty
  if (payload.mode === 'hybrid' && payload.hybrid_mask && (!payload.mask || payload.mask.trim() === '')) {
    payload.mask = payload.hybrid_mask;
  }
  
  // Map field names for new attack modes
  if (payload.hybrid_mode) {
    payload.hybrid_mode = payload.hybrid_mode.replace('_', '-'); // wordlist_mask -> wordlist-mask
  }
  
  return payload;
}

function validatePayload(payload) {
  if (!payload.target || !payload.target.trim()) {
    showToast('please enter a target hash', 'error');
    showStep(1);
    return false;
  }
  
  if (!payload.algo || payload.algo === '') {
    showToast('please select the algorithm', 'error');
    showStep(1);
    return false;
  }
  
  if (payload.mode === 'wordlist') {
    if (payload.use_default_wordlist) {
      if ((payload.wordlist && payload.wordlist.trim() !== '') || (payload.wordlist_url && payload.wordlist_url.trim() !== '')) {
        showToast('choose either default wordlist or custom upload/URL, not both', 'error');
        showStep(2);
        return false;
      }
    } else {
      const hasWordlistPath = payload.wordlist && payload.wordlist.trim() !== '';
      const hasWordlistUrl = payload.wordlist_url && payload.wordlist_url.trim() !== '';
      const hasDefault = payload.use_default_wordlist;
      
      if (!hasWordlistPath && !hasWordlistUrl && !hasDefault) {
        showToast('please select a wordlist source', 'error');
        showStep(2);
        return false;
      }
    }
  } else if (payload.mode === 'mask') {
    if (!payload.mask || payload.mask.trim() === '') {
      showToast('please enter a mask pattern', 'error');
      showStep(2);
      return false;
    }
  } else if (payload.mode === 'bruteforce') {
    if (!payload.bf_chars || payload.bf_chars.trim() === '') {
      showToast('please select character set', 'error');
      showStep(2);
      return false;
    }
  }
  
  return true;
}

async function stopTask(id) {
  try {
    const resp = await fetch(`/api/tasks/${id}/stop`, { method: 'POST' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    showToast('Task stopped', 'success');
    await loadTasks();
  } catch (error) {
    console.error('Failed to stop task:', error);
    showToast('Failed to stop task', 'error');
  }
}

async function pauseTask(id) {
  try {
    const resp = await fetch(`/api/tasks/${id}/pause`, { method: 'POST' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    showToast('Task paused', 'success');
    await loadTasks();
  } catch (error) {
    console.error('Failed to pause task:', error);
    showToast('Failed to pause task', 'error');
  }
}

async function resumeTask(id) {
  try {
    showToast('Resuming task...', 'info');
    const resp = await fetch(`/api/tasks/${id}/resume`, { method: 'POST' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    showToast('Task resumed successfully', 'success');
    await loadTasks();
  } catch (error) {
    console.error('Failed to resume task:', error);
    showToast('Failed to resume task', 'error');
  }
}

async function deleteTask(id) {
  if (!confirm('Delete this task permanently?')) return;
  
  try {
    const resp = await fetch(`/api/tasks/${id}`, { method: 'DELETE' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    showToast('Task deleted', 'success');
    await loadTasks();
  } catch (error) {
    console.error('Failed to delete task:', error);
    showToast('Failed to delete task', 'error');
  }
}

function renderTasks(tasks) {
  const tbody = document.querySelector('#tasks tbody');
  if (!tbody) return;
  
  const next = [];
  for (const t of tasks) {
    const tr = document.createElement('tr');
    
    let progress = '';
    let result = '';
    
    // Check for cache usage events
    const cacheEvents = t.events?.filter(e => e.event === 'cache_used') || [];
    let cacheIndicator = '';
    if (cacheEvents.length > 0) {
      const cacheTypes = cacheEvents.map(e => e.wordlist_type || 'wordlist').join(', ');
      cacheIndicator = `<span class="cached-indicator" title="Using cached wordlist(s): ${cacheTypes}">Cached</span>`;
    }
    
    if (t.download && t.download.active) {
      // Show download progress
      const percent = t.download.percent || 0;
      const speed = formatBytes(t.download.speed_bps || 0) + '/s';
      progress = `
        <div class="progress-container">
          <div class="progress-bar">
            <div class="progress-fill" style="width: ${percent}%"></div>
          </div>
          <small class="muted">Downloading... ${percent.toFixed(1)}% (${speed})</small>
        </div>
      `;
    } else if (t.progress) {
      const percent = t.progress.progress_percent || 0;
      const speed = formatSpeed(t.progress.attempts_per_second);
      const tried = formatNumber(t.progress.tried);
      const total = t.progress.total ? formatNumber(t.progress.total) : '?';
      
      let eta = '';
      if (t.progress.eta_seconds > 0 && t.progress.eta_seconds < 31536000) {
        eta = ` - ETA: ${formatTime(t.progress.eta_seconds * 1000)}`;
      }
      
      const progressBarWidth = Math.min(100, Math.max(0, percent));
      
      progress = `
        <div class="progress-container">
          <div class="progress-bar">
            <div class="progress-fill ${t.status === 'running' ? 'animating' : ''}" style="width: ${progressBarWidth}%"></div>
          </div>
          <small class="progress-text">${tried}/${total} (${percent.toFixed(1)}%) - ${speed}${eta}</small>
        </div>
      `;
    } else if (t.result) {
      const tried = formatNumber(t.result.tried);
      const durMs = t.result.duration_ns / 1000000;
      const duration = durMs > 0 ? ` (${formatTime(durMs)})` : '';
      progress = `<small class="muted">${formatNumber(tried)} attempts${duration}</small>`;
    }
    
    if (t.result) {
      if (t.result.found) {
        result = `<span class="text-success"><strong>${t.result.plaintext}</strong></span>`;
      } else {
        result = `<span class="text-muted">Not found</span>`;
      }
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
      <td class="progress-column">
        ${progress}
        ${cacheIndicator}
      </td>
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
      return `<small class="mode-badge mode-bruteforce"><i class="fas fa-hammer"></i> Brute Force (${task.bf_min || 1}-${task.bf_max || 1} chars)</small>`;
    case 'wordlist':
      const source = task.use_default_wordlist ? 'default' : task.wordlist || 'custom';
      return `<small class="mode-badge mode-wordlist"><i class="fas fa-list"></i> Dictionary (${source})</small>`;
    case 'combination':
      return `<small class="mode-badge mode-combination"><i class="fas fa-link"></i> Combination</small>`;
    case 'hybrid':
      return `<small class="mode-badge mode-hybrid"><i class="fas fa-puzzle-piece"></i> Hybrid</small>`;
    case 'association':
      return `<small class="mode-badge mode-association"><i class="fas fa-brain"></i> Association</small>`;
    default:
      return `<small class="mode-badge">${mode}</small>`;
  }
}

// Step navigation
function showStep(step) {
  document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.step-indicator').forEach(s => s.classList.remove('active'));
  
  const stepEl = document.getElementById(`step${step}`);
  const indicatorEl = document.querySelector(`.step-indicator[data-step="${step}"]`);
  
  if (stepEl) stepEl.classList.add('active');
  if (indicatorEl) indicatorEl.classList.add('active');
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  // Setup method cards
  document.querySelectorAll('.method-card').forEach(card => {
    card.addEventListener('click', function() {
      document.querySelectorAll('.method-card').forEach(c => c.classList.remove('selected'));
      this.classList.add('selected');
      
      const method = this.dataset.method;
      const radio = document.getElementById(`method-${method}`);
      if (radio) radio.checked = true;
      
      // Show/hide method-specific options
      document.querySelectorAll('.method-options').forEach(opt => {
        opt.style.display = 'none';
      });
      
      const methodOptions = document.getElementById(`${method}-options`);
      if (methodOptions) {
        methodOptions.style.display = 'block';
      }
    });
  });
  
  // Brute force complexity calculator
  const bfMinInput = document.querySelector('input[name="bf_min"]');
  const bfMaxInput = document.querySelector('input[name="bf_max"]');
  const bfCharsInput = document.querySelector('input[name="bf_chars"]');
  const estimatedAttempts = document.getElementById('estimatedAttempts');
  
  function updateComplexity() {
    if (!bfMinInput || !bfMaxInput || !bfCharsInput || !estimatedAttempts) return;
    
    const min = parseInt(bfMinInput.value) || 1;
    const max = parseInt(bfMaxInput.value) || 1;
    const chars = bfCharsInput.value.length || 1;
    
    let total = 0;
    for (let len = min; len <= max; len++) {
      total += Math.pow(chars, len);
    }
    
    estimatedAttempts.textContent = formatNumber(total);
  }
  
  if (bfMinInput) bfMinInput.addEventListener('input', updateComplexity);
  if (bfMaxInput) bfMaxInput.addEventListener('input', updateComplexity);
  if (bfCharsInput) bfCharsInput.addEventListener('input', updateComplexity);
  
  // Initialize method selection
  const defaultMethodCard = document.querySelector('.method-card[data-method="wordlist"]');
  if (defaultMethodCard) {
    defaultMethodCard.click();
  }
  
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

// Global utility functions
window.nextStep = function(step) {
  showStep(step);
};

window.prevStep = function(step) {
  showStep(step);
};

window.setCharset = function(charset) {
  const bfCharsInput = document.querySelector('input[name="bf_chars"]');
  if (bfCharsInput) {
    bfCharsInput.value = charset;
    bfCharsInput.dispatchEvent(new Event('input'));
  }
};

// URL validation function
function isValidUrl(string) {
  try {
    const url = new URL(string);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

// Set wordlist URL from shortcut buttons
window.setWordlistUrl = function(inputIdOrUrl, url) {
  let urlInput, urlToSet;
  
  // Handle both old and new function signatures
  if (arguments.length === 1) {
    // Old signature: setWordlistUrl(url)
    urlInput = document.getElementById('wordlistUrl');
    urlToSet = inputIdOrUrl;
  } else {
    // New signature: setWordlistUrl(inputId, url)
    urlInput = document.getElementById(inputIdOrUrl);
    urlToSet = url;
  }
  
  if (urlInput) {
    urlInput.value = urlToSet;
    urlInput.dispatchEvent(new Event('input'));
    
    // Show validation status in the matching section
    validateWordlistUrlInternal(urlToSet, urlInput.id);
  }
};

// Wrapper function for validating URL by input element ID
window.validateWordlistUrl = function(inputIdOrUrl) {
  let url, inputId = null;
  if (typeof inputIdOrUrl === 'string' && inputIdOrUrl.startsWith('http')) {
    url = inputIdOrUrl;
  } else {
    inputId = inputIdOrUrl;
    const input = document.getElementById(inputIdOrUrl);
    if (!input) return;
    url = input.value.trim();
  }
  validateWordlistUrlInternal(url, inputId);
};

// Validate wordlist URL (internal function) - SIMPLIFIED
async function validateWordlistUrlInternal(url, inputId) {
  // Choose the correct status elements based on which input is being validated
  let statusDiv = document.getElementById('urlStatus');
  let statusText = document.getElementById('urlStatusText');
  let statusIndicator = statusDiv;
  
  if (inputId === 'combWordlist1Url') {
    statusDiv = document.getElementById('combWL1Status');
    statusText = document.getElementById('combWL1StatusText');
  } else if (inputId === 'combWordlist2Url') {
    statusDiv = document.getElementById('combWL2Status');
    statusText = document.getElementById('combWL2StatusText');
  } else if (inputId === 'hybridWordlistUrl') {
    statusDiv = document.getElementById('hybridWLStatus');
    statusText = document.getElementById('hybridWLStatusText');
  }
  
  if (!statusDiv || !statusText) return;
  
  statusIndicator = statusDiv;
  
  if (!url) {
    statusIndicator.className = 'status-indicator';
    statusText.innerHTML = '<i class="fas fa-info-circle"></i> Enter a URL to validate';
    return;
  }
  
  if (!isValidUrl(url)) {
    statusIndicator.className = 'status-indicator error';
    statusText.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Invalid URL format';
    return;
  }
  
  statusIndicator.className = 'status-indicator';
  statusText.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Validating URL...';
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch('/api/validate-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      // SIMPLIFIED SUCCESS MESSAGE
      statusIndicator.className = 'status-indicator success';
      statusText.innerHTML = `<i class="fas fa-check-circle"></i> URL is valid and accessible`;
    } else {
      statusIndicator.className = 'status-indicator error';
      statusText.innerHTML = `<i class="fas fa-exclamation-triangle"></i> URL not accessible (${response.status})`;
    }
  } catch (error) {
    // Only show error messages, not success messages
    if (error.name === 'AbortError') {
      statusIndicator.className = 'status-indicator warning';
      statusText.innerHTML = `<i class="fas fa-clock"></i> Validation timeout - URL may be slow`;
    } else {
      statusIndicator.className = 'status-indicator error';
      statusText.innerHTML = `<i class="fas fa-exclamation-triangle"></i> Failed to validate URL`;
    }
  }
}

// Toggle advanced algorithm parameters
function debounce(fn, delay = 300) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), delay);
  };
}

document.addEventListener('DOMContentLoaded', () => {
  const ids = ['wordlistUrl', 'hybridWordlistUrl', 'combWordlist1Url', 'combWordlist2Url'];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', debounce(() => validateWordlistUrl(id), 500));
    }
  });
});

window.toggleAdvancedParams = function() {
  const content = document.getElementById('advanced-params');
  const button = document.querySelector('.toggle-advanced');
  const icon = button.querySelector('i');
  
  if (content.style.display === 'none') {
    content.style.display = 'block';
    button.innerHTML = '<i class="fas fa-chevron-up"></i> Hide Advanced Parameters';
    button.classList.add('expanded');
  } else {
    content.style.display = 'none';
    button.innerHTML = '<i class="fas fa-chevron-down"></i> Show Advanced Parameters';
    button.classList.remove('expanded');
  }
};

window.showStep = showStep;