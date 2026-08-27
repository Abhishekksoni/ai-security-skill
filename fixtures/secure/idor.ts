// AUTHZ-001: Missing server-side resource authorization (IDOR/BOLA)
export async function getProperty(req: any, res: any, db: any) {
  const propertyId = req.query.id;
  const session = req.session; // Auth check
  
  if (!session || !session.userId) {
    return res.status(401).send('Unauthorized');
  }

  // SECURE: Enforce ownership check in the query criteria
  const property = await db.property.findUnique({
    where: { 
      id: propertyId,
      ownerId: session.userId // Tenant/owner verification limit
    }
  });
  
  if (!property) {
    return res.status(404).send('Not Found');
  }
  
  return res.json(property);
}
