// AI-004: Improper output handling
export async function executeModelCommand(llmResponse: string) {
  // SECURE: Parse response dynamically as JSON and validate arguments strictly
  const parsed = JSON.parse(llmResponse);
  const action = parsed.action;
  
  const allowedActions = ['view', 'list'];
  if (!allowedActions.includes(action)) {
    throw new Error('Unsupported output action requested');
  }
  
  return { status: 'success', action };
}
