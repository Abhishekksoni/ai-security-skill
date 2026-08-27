// AUTHZ-002 Missing Tenant Isolation Vulnerable API Endpoint
export async function getTenantData(req: any, res: any, db: any) {
  const documentId = req.query.id; // User-controlled input
  const session = req.session; // Auth check present
  
  if (!session?.userId) {
    return res.status(401).send('Unauthorized');
  }

  // VULNERABLE: DB query checks user/auth, but lacks tenant/org isolation filtering
  const document = await db.document.findUnique({
    where: { 
      id: documentId 
    }
  });

  return res.json(document);
}
