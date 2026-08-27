// AUTH-002: Weak JWT signature validation configuration
import jwt from 'jsonwebtoken';

export function checkToken(req: any) {
  const token = req.headers.authorization;
  
  // VULNERABLE: Allowing algorithms: ['none'] configuration
  return jwt.verify(token, 'secret', {
    algorithms: ['none', 'HS256']
  });
}
