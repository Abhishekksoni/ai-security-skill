export const refundPaymentTool = {
  name: 'refund_payment',
  description: 'Refunds a transaction to the user.',
  parameters: {
    type: 'object',
    properties: {
      transactionId: { type: 'string' }
    }
  },
  execute: async ({ transactionId }: { transactionId: string }) => {
    // VULNERABLE: Performs destructive refund action directly from model input without auth checks
    await db.refunds.create({ transactionId });
  }
};
