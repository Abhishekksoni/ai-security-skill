// AUTH-002: Weak JWT signature validation configuration
import jwt from 'jsonwebtoken';

export function checkToken(req: any) {
  const token = req.headers.authorization;
  
  // SECURE: Enforcing signature checking and restricting algorithms
  return jwt.verify(token, 'secure-key-phrase', {
    algorithms: ['HS256']
  });
}
