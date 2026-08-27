import jwt from 'jsonwebtoken';

export function verifyUserToken(token: string) {
  // Vulnerable to signature bypass via "none" algorithm selection
  return jwt.verify(token, 'secret-key', {
    algorithms: ['none', 'HS256']
  });
}
