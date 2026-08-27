// INJ-003: SQL Injection via template string interpolation
export async function searchProperties(req: any, db: any) {
  const queryTerm = req.query.term;
  
  // SECURE: Parameterized query arguments
  const results = await db.query(
    'SELECT * FROM properties WHERE name LIKE ?',
    [`%${queryTerm}%`]
  );
  return results;
}
