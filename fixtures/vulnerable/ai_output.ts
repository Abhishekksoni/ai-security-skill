// AI-004: Improper output handling
export async function executeModelCommand(llmResponse: string) {
  // VULNERABLE: Direct eval execution of model output string
  eval(llmResponse);
}
