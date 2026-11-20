export function detectPeopleKind(value) {
  const s = String(value || '').trim();
  if (!s) return null;
  if (s.includes('@') && !/\s/.test(s)) return 'email';
  if (/^\+?[\d\s()-]{7,20}$/.test(s) && s.replace(/\D/g, '').length >= 7) return 'phone';
  if (/^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}\/.+/i.test(s)) return 'profile_url';
  if (/\s/.test(s)) return 'real_name';
  if (!/[./:]/.test(s) && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{1,31}$/.test(s)) return 'username';
  return null;
}
