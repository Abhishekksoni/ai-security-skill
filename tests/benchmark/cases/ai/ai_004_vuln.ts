export function handleModelResponse(llmResponse: string) {
  // VULNERABLE: Direct dynamic code execution of LLM output
  eval(llmResponse);
}
