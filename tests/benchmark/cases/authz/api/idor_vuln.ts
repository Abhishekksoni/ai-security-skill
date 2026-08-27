// AUTHZ-001 IDOR Vulnerable API Endpoint
export async function getInvoice(req: any, res: any, db: any) {
  const invoiceId = req.params.id; // User-controlled input
  
  // VULNERABLE: Database query with no authentication or session check
  const invoice = await db.invoice.findUnique({
    where: { id: invoiceId }
  });
  
  return res.json(invoice);
}
