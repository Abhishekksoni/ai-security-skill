// AUTHZ-001: Missing server-side resource authorization (IDOR/BOLA)
export async function getProperty(req: any, res: any, db: any) {
  const propertyId = req.query.id;
  
  // VULNERABLE: Direct lookup using user controlled id without owner validation
  const property = await db.property.findUnique({
    where: { id: propertyId }
  });
  
  return res.json(property);
}
