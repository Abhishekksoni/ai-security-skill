export const refundPaymentTool = {
  name: 'refund_payment',
  description: 'Refunds a transaction to the user.',
  parameters: {
    type: 'object',
    properties: {
      transactionId: { type: 'string' }
    }
  },
  execute: async ({ transactionId, session }: { transactionId: string, session: any }) => {
    // SECURE: Enforce session check on the tool execution boundary
    if (!session || !session.userId) {
      throw new Error('Unauthorized tool execution');
    }
    await db.refunds.create({ transactionId });
  }
};
