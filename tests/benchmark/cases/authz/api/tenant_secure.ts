// AUTHZ-002 Tenant Isolation Secure API Endpoint
export async function getTenantData(req: any, res: any, db: any) {
  const documentId = req.query.id; // User-controlled input
  const session = req.session; // Auth check present
  
  if (!session?.userId || !session.tenantId) {
    return res.status(401).send('Unauthorized');
  }

  // SECURE: Strictly filter query by tenantId to prevent cross-tenant data leakage
  const document = await db.document.findUnique({
    where: { 
      id: documentId,
      tenantId: session.tenantId // Tenant Isolation filter
    }
  });

  return res.json(document);
}
