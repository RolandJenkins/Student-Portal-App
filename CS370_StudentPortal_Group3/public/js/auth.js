function getCurrentUser() {
  try { return JSON.parse(sessionStorage.getItem('currentUser') || 'null'); }
  catch { return null; }
}
function isAuthenticated() {
  const u = getCurrentUser();
  return !!(u && u.username && u.role);
}
async function login(username, password, userType) {
  const resp = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, userType })
  });
  if (!resp.ok) {
    let err = await resp.json().catch(()=>({message:'Login failed'}));
    throw new Error(err.message || 'Login failed');
  }
  const data = await resp.json();
  sessionStorage.setItem('currentUser', JSON.stringify(data));
  return data;
}
function logout() {
  sessionStorage.removeItem('currentUser');
}
