export async function searchProperties(db: any, queryTerm: string) {
  // SECURE: Use parameterized SQL query to prevent injection
  const results = await db.query('SELECT * FROM properties WHERE name LIKE ?', [`%${queryTerm}%`]);
  return results;
}
