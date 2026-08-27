// AI-001: Prompt Injection Vulnerability
export function generateSystemPrompt(userInput: string) {
  const systemPrompt = `You are a helpful assistant. User request: ${userInput}`;
  return systemPrompt;
}
