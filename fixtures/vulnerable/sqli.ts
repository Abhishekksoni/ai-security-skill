// INJ-003: SQL Injection via unescaped template string interpolation
export async function searchProperties(req: any, db: any) {
  const queryTerm = req.query.term;
  
  // VULNERABLE: Direct string interpolation inside raw sql query
  const results = await db.query(`SELECT * FROM properties WHERE name LIKE '%${queryTerm}%'`);
  return results;
}
