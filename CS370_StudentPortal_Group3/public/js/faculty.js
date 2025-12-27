// faculty.js
// Handles faculty-side student record management

async function populateStudentsTable() {
  const table = document.getElementById('studentsTable');
  if (!table) return;
  table.innerHTML = '';
  try {
    const resp = await fetch('/api/students');
    const rows = await resp.json();
    rows.forEach(s => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${s.bluegold_id}</td>
        <td>${s.full_name}</td>
        <td>${s.gpa ?? ''}</td>
        <td>${s.total_credits ?? ''}</td>
        <td>$${Number(s.account_balance || 0).toFixed(2)}</td>
        <td>
          <button class="btn" style="padding: 5px 10px;" onclick="updateStudentGPA('${s.bluegold_id}')">GPA</button>
          <button class="btn" style="padding: 5px 10px; background-color: var(--warning);" onclick="updateStudentCredits('${s.bluegold_id}', ${s.total_credits ?? 0})">Credits</button>
          <button class="btn" style="padding: 5px 10px; background-color: var(--success);" onclick="chargeTuition('${s.bluegold_id}')">Charge</button>
        </td>
      `;
      table.appendChild(tr);
    });
  } catch (e) {
    console.error(e);
  }
}

function filterStudents() {
  const searchTerm = document.getElementById('searchStudent').value.toLowerCase();
  const rows = document.getElementById('studentsTable').getElementsByTagName('tr');
  for (let i = 0; i < rows.length; i++) {
    const text = rows[i].textContent.toLowerCase();
    rows[i].style.display = text.includes(searchTerm) ? '' : 'none';
  }
}

// Attach once in addStudent.html: document.getElementById('addStudentForm').addEventListener('submit', addNewStudent);

async function addNewStudent(e) {
  e.preventDefault();

  const name     = document.getElementById('newStudentName').value.trim();
  const id       = document.getElementById('newStudentID').value.trim();
  const address  = document.getElementById('newStudentAddress').value.trim();
  const phoneRaw = document.getElementById('newStudentPhone').value.trim();
  const email    = document.getElementById('newStudentEmail').value.trim();
  const username = document.getElementById('newStudentUsername').value.trim();
  const password = document.getElementById('newStudentPassword').value;

  const alertEl = document.getElementById('addStudentAlert');

  // Basic required fields
  if (!name || !id || !username || !password) {
    return showAlert(alertEl, 'Full name, BlueGold ID, username, and password are required.', 'error');
  }

  // Phone: exactly 10 digits
  const phoneDigits = phoneRaw.replace(/\D/g, '');
  if (phoneDigits.length !== 10) {
    return showAlert(alertEl, 'Phone number must be exactly 10 digits.', 'error');
  }

  // Email must end with @uwec.edu
  if (!/@uwec\.edu$/i.test(email)) {
    return showAlert(alertEl, 'Email must end with @uwec.edu.', 'error');
  }

  try {
    const actor = getCurrentUser();
    const resp = await fetch('/api/students', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        full_name: name,
        bluegold_id: id,
        address,
        phone: phoneDigits,
        email,
        username,
        password,
        // optional logging metadata
        actorUsername: actor?.username,
        actorRole: actor?.role
      })
    });

    const data = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      return showAlert(alertEl, data.message || 'Failed to add student.', 'error');
    }

    showAlert(alertEl, `Student ${name} (${id}) added successfully.`, 'success');
    e.target.reset();

    // If table present, refresh
    if (typeof populateStudentsTable === 'function') {
      populateStudentsTable();
    }
  } catch (err) {
    console.error(err);
    showAlert(alertEl, 'Server error adding student.', 'error');
  }
}


async function updateStudentGPA(id) {
  const actor = getCurrentUser();
  const newGPA = prompt(`Enter new GPA for ${id}:`);
  const val = Number(newGPA);
  if (isNaN(val) || val < 0 || val > 4.0) return alert('Enter a valid GPA between 0.0 and 4.0');

  const resp = await fetch(`/api/students/${encodeURIComponent(id)}/gpa`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ gpa: val, actorUsername: actor.username, actorRole: actor.role })
  });
  if (resp.ok) {
    alert('GPA updated');
    populateStudentsTable();
  } else {
    alert('Failed to update GPA');
  }
}

async function updateStudentCredits(bluegold_id, currentCredits) {
  const user = getCurrentUser();
  const newCredits = prompt("Enter the new total credits for this student:", currentCredits);

  if (newCredits === null) return; // User canceled

  const parsed = parseInt(newCredits, 10);
  if (isNaN(parsed) || parsed < 0) {
    alert("Please enter a valid non-negative number for credits.");
    return;
  }

  // ✅ Restrict to a maximum of 200 credits
  if (parsed > 200) {
    alert("Error: Total credits cannot exceed 200.");
    return;
  }

  try {
    const res = await fetch(`/api/students/${encodeURIComponent(bluegold_id)}/credits`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        total_credits: parsed,
        actorUsername: user.username,
        actorRole: user.role
      })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ message: "Update failed" }));
      throw new Error(err.message);
    }

    const updated = await res.json();
    alert(`✅ Credits updated to ${updated.total_credits}.`);
    logActivity(`${user.username} updated credits for ${bluegold_id} to ${parsed}`);
    populateStudentsTable(); // refresh table
  } catch (e) {
    console.error(e);
    alert("An error occurred while updating credits.");
  }
}


async function chargeTuition(id) {
  const actor = getCurrentUser();
  const amount = prompt(`Enter amount to charge (negative to credit):`);
  const val = Number(amount);
  if (!Number.isFinite(val)) return alert('Enter a valid number');

  try {
    // Optional UX precheck: fetch current balance to avoid a failing request
    const curRes = await fetch(`/api/student?bluegold=${encodeURIComponent(id)}`);
    if (!curRes.ok) throw new Error('Failed to read current balance');
    const cur = await curRes.json();
    const currentBalance = Number(cur.account_balance || 0);
    const projected = currentBalance + val;

    if (projected < 0) {
      return alert(
        `That credit would drop the balance below $0.\nCurrent: $${currentBalance.toFixed(2)}, credit: $${val.toFixed(2)}.`
      );
    }

    const resp = await fetch(`/api/students/${encodeURIComponent(id)}/charge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: val, actorUsername: actor.username, actorRole: actor.role })
    });

    if (resp.ok) {
      const updated = await resp.json();
      alert(`Account balance updated. New balance: $${Number(updated.account_balance).toFixed(2)}`);
      populateStudentsTable();
    } else {
      const err = await resp.json().catch(() => ({ message: 'Failed to update balance' }));
      alert(err.message || 'Failed to update balance');
    }
  } catch (e) {
    console.error(e);
    alert('An error occurred while updating balance.');
  }
}

