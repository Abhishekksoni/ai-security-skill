export function handleModelResponse(llmResponse: string) {
  // SECURE: Parse LLM response safely as JSON without evaluating it as code
  const parsed = JSON.parse(llmResponse);
  return parsed;
}
