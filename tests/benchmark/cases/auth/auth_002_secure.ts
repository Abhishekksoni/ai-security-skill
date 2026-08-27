import jwt from 'jsonwebtoken';

export function verifyUserToken(token: string) {
  // Secure: disallow none algorithm, strictly validate with HS256
  return jwt.verify(token, 'secret-key', {
    algorithms: ['HS256']
  });
}
