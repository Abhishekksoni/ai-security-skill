// AI-002 / AI-005: Excessive Agency & Tool Authorization Bypass
export const refundPaymentTool = {
  name: 'refund_payment',
  description: 'Refunds a transaction using transactionId.',
  parameters: {
    type: 'object',
    properties: {
      transactionId: { type: 'string' }
    }
  },
  
  // SECURE: Validates user session credentials and requests human confirmation
  handler: async (args: any, context: any) => {
    const session = context.session;
    if (!session || !session.userId || session.role !== 'admin') {
      throw new Error('Unauthorized tool execution context');
    }
    
    // Check human approval flag
    if (!context.humanApproved) {
      return {
        status: 'PENDING_APPROVAL',
        message: 'Refund action requires explicit human user confirmation.'
      };
    }
    
    return await context.payments.refund(args.transactionId);
  }
};
