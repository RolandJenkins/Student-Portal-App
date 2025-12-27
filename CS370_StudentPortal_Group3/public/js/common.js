// Common utility functions
let activityLog = JSON.parse(sessionStorage.getItem('activityLog')) || [];

function updateTime() {
    const now = new Date();
    const timeElement = document.getElementById('currentTime');
    if (timeElement) {
        timeElement.textContent = now.toLocaleString();
    }
}

// ===== Activity utilities (server-backed) =====
async function logActivity(activity) {
  try {
    const u = (typeof getCurrentUser === 'function') ? getCurrentUser() : null;
    await fetch('/api/activity', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: u?.username || null,
        role: u?.role || null,
        activity
      })
    });
  } catch (e) {
    console.error('logActivity failed', e);
  }
}

// Render helper
function renderActivityRows(entries, tableBodyId = 'activityLog') {
  const tbody = document.getElementById(tableBodyId);
  if (!tbody) return;
  tbody.innerHTML = '';
  entries.forEach(e => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${new Date(e.ts).toLocaleString()}</td>
      <td>${e.activity}</td>
      <td>${e.username ? `${e.username} (${e.role || 'unknown'})` : 'System'}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Fetch only THIS user's activity
async function fetchMyActivity(limit = 10) {
  try {
    const u = (typeof getCurrentUser === 'function') ? getCurrentUser() : null;
    if (!u?.username) return renderActivityRows([]);
    const resp = await fetch(`/api/activity/user/${encodeURIComponent(u.username)}?limit=${limit}`);
    const data = await resp.json();
    renderActivityRows(Array.isArray(data) ? data : []);
  } catch (e) {
    console.error('fetchMyActivity failed', e);
    renderActivityRows([]);
  }
}

// Fetch ALL activity (faculty)
async function fetchAllActivity(limit = 25) {
  try {
    const resp = await fetch(`/api/activity/all?limit=${limit}`);
    const data = await resp.json();
    renderActivityRows(Array.isArray(data) ? data : []);
  } catch (e) {
    console.error('fetchAllActivity failed', e);
    renderActivityRows([]);
  }
}


function showAlert(alertElement, message, type) {
    if (!alertElement) return;
    
    alertElement.textContent = message;
    alertElement.className = 'alert';
    
    if (type === 'success') {
        alertElement.classList.add('alert-success');
    } else if (type === 'error') {
        alertElement.classList.add('alert-error');
    }
    
    alertElement.style.display = 'block';
    
    setTimeout(() => {
        alertElement.style.display = 'none';
    }, 5000);
}

// ===== Account Password Management (shared) =====
async function changePassword(e) {
  e.preventDefault();
  const alertEl = document.getElementById('accountAlert');
  const user = getCurrentUser();

  if (!user) {
    showAlert(alertEl, 'Session expired. Please log in again.', 'error');
    window.location.href = 'home.html';
    return;
  }

  const currentPassword = document.getElementById('currentPassword').value;
  const newPassword     = document.getElementById('newPassword').value;
  const confirmPassword = document.getElementById('confirmPassword').value;

  // Client-side checks
  if (newPassword.length < 8) {
    return showAlert(alertEl, 'New password must be at least 8 characters.', 'error');
  }
  if (newPassword !== confirmPassword) {
    return showAlert(alertEl, 'New password and confirmation do not match.', 'error');
  }
  if (newPassword === currentPassword) {
    return showAlert(alertEl, 'New password must be different from current.', 'error');
  }

  try {
    const resp = await fetch('/api/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: user.username,
        role: user.role,
        currentPassword,
        newPassword
      })
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      return showAlert(alertEl, data.message || 'Password change failed.', 'error');
    }

    showAlert(alertEl, 'Password updated successfully.', 'success');
    document.getElementById('changePasswordForm').reset();
    logActivity(`${user.username} changed password`);
  } catch (err) {
    console.error(err);
    showAlert(alertEl, 'Server error while changing password.', 'error');
  }
}
