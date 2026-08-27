export function generateSystemPrompt(userInput: string) {
  // VULNERABLE: Direct template literal interpolation without delimiters or validation
  const prompt = `You are a helpful assistant. User request: ${userInput}`;
  return prompt;
}
