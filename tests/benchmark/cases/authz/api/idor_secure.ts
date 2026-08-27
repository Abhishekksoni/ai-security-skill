// AUTHZ-001 IDOR Secure API Endpoint
export async function getInvoice(req: any, res: any, db: any) {
  const invoiceId = req.params.id; // User-controlled input
  const session = req.session; // Auth check present
  
  if (!session?.userId) {
    return res.status(401).send('Unauthorized');
  }
  
  // SECURE: Enforce owner constraint in the database query
  const invoice = await db.invoice.findUnique({
    where: { 
      id: invoiceId,
      ownerId: session.userId 
    }
  });
  
  return res.json(invoice);
}
