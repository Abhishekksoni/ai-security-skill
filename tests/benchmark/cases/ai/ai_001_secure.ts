export function generateSystemPrompt(userInput: string) {
  // SECURE: Wrap input in clear XML tags to delineate system prompt from user payload
  const prompt = `You are a helpful assistant.
Format your actions based on user instructions.
<user_input>
${userInput}
</user_input>`;
  return prompt;
}
