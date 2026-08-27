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
  
  // VULNERABLE: Tool executes sensitive action directly without auth checks
  handler: async (args: any, context: any) => {
    return await context.payments.refund(args.transactionId);
  }
};
