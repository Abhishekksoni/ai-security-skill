// INJ-001 Dynamic Code Execution via eval()
export function runCalculator(inputString: string) {
  // VULNERABLE: Direct dynamic code execution
  return eval(inputString);
}
