export async function searchProperties(db: any, queryTerm: string) {
  // VULNERABLE: SQL query built via template literal interpolation
  const results = await db.query(`SELECT * FROM properties WHERE name LIKE '%${queryTerm}%'`);
  return results;
}
