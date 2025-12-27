// student.js
// Handles student self-updates (My Information page)
// Editable: full_name, address, phone
// Not editable: bluegold_id, email, gpa, total_credits

let ORIGINAL_BLUE_ID = null;

document.addEventListener('DOMContentLoaded', () => {
  const user = getCurrentUser();
  if (!user || user.role !== 'student') {
    window.location.href = 'home.html';
    return;
  }

  loadStudentInfo(user.username);

  document.getElementById('editInfoBtn').addEventListener('click', enableEdit);
  document.getElementById('saveInfoBtn').addEventListener('click', saveStudentInfo);
  document.getElementById('cancelEditBtn').addEventListener('click', cancelEdit);
});

async function loadStudentInfo(username) {
  try {
    const res = await fetch(`/api/student?username=${encodeURIComponent(username)}`);
    if (!res.ok) throw new Error('Failed to load student info');
    const data = await res.json();

    ORIGINAL_BLUE_ID = data.bluegold_id || null;

    // Fill fields
    setVal('studentName',    data.full_name || '');
    setVal('bluegoldID',     data.bluegold_id || '');
    setVal('studentAddress', data.address || '');
    setVal('studentPhone',   sanitizeDigits(data.phone || '')); // show digits only
    setVal('studentEmail',   data.email || '');
    setVal('studentGPA',     data.gpa ?? '');
    setVal('studentCredits', data.total_credits ?? '');
  } catch (e) {
    console.error(e);
    showAlert(document.getElementById('studentInfoAlert'), 'Failed to load data', 'error');
  }
}

function setVal(id, v) {
  const el = document.getElementById(id);
  if (el) el.value = v;
}

function enableEdit() {
  // Only allow these to be edited
  ['studentName', 'studentAddress', 'studentPhone'].forEach(id => {
    document.getElementById(id).removeAttribute('readonly');
  });

  // Ensure these remain locked
  ['bluegoldID', 'studentEmail', 'studentGPA', 'studentCredits'].forEach(id => {
    const el = document.getElementById(id);
    el.setAttribute('readonly', true);
  });

  document.getElementById('saveInfoBtn').style.display = 'inline-block';
  document.getElementById('cancelEditBtn').style.display = 'inline-block';
}

function cancelEdit() {
  const user = getCurrentUser();
  loadStudentInfo(user.username);
  disableEdit();
}

function disableEdit() {
  ['studentName', 'studentAddress', 'studentPhone', 'bluegoldID',
   'studentEmail', 'studentGPA', 'studentCredits'
  ].forEach(id => {
    document.getElementById(id).setAttribute('readonly', true);
  });
  document.getElementById('saveInfoBtn').style.display = 'none';
  document.getElementById('cancelEditBtn').style.display = 'none';
}

// keep digits only
function sanitizeDigits(s) {
  return String(s || '').replace(/\D/g, '');
}

async function saveStudentInfo() {
  const user = getCurrentUser();
  if (!ORIGINAL_BLUE_ID) {
    showAlert(document.getElementById('studentInfoAlert'), 'Original record not loaded', 'error');
    return;
  }

  const full_name = document.getElementById('studentName').value.trim();
  const address   = document.getElementById('studentAddress').value.trim();
  const phoneRaw  = document.getElementById('studentPhone').value.trim();

  // Validate 10 digits only
  const phoneDigits = String(phoneRaw).replace(/\D/g, '');
  if (phoneDigits.length !== 10) {
    showAlert(document.getElementById('studentInfoAlert'), 'Phone number must be exactly 10 digits.', 'error');
    return;
  }

  try {
    // ✅ This is where your fetch() call goes
    const res = await fetch(`/api/student/${encodeURIComponent(ORIGINAL_BLUE_ID)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        full_name,
        address,
        phone: phoneDigits,
        actorUsername: user.username,
        actorRole: user.role
      })
    });

    if (!res.ok) {
      const err = await res.json().catch(()=>({message:'Save failed'}));
      throw new Error(err.message || 'Save failed');
    }

    const updated = await res.json();

    showAlert(document.getElementById('studentInfoAlert'), 'Information updated successfully', 'success');
    disableEdit();

    logActivity(`${user.username} updated personal info`);
  } catch (e) {
    console.error(e);
    showAlert(document.getElementById('studentInfoAlert'), e.message || 'Error saving info', 'error');
  }
}
