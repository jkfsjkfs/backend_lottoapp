import bcrypt from 'bcryptjs';

export async function verifyPassword(inputPassword, storedPasswordHash) {
  const allowPlain = String(process.env.PLAIN_ALLOWED || '').toLowerCase() === 'true';

  if (storedPasswordHash && storedPasswordHash.startsWith('$2')) {
    try {
      const ok = await bcrypt.compare(inputPassword, storedPasswordHash);
      if (ok) return true;
    } catch { /* ignore */ }
  }

  if (allowPlain) {
    return inputPassword === storedPasswordHash;
  }

  return false;
}
