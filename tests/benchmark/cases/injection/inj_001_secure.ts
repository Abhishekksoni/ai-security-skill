// INJ-001 Safe Parsing
export function runCalculator(inputString: string) {
  // SECURE: Parse data structure safely
  return JSON.parse(inputString);
}
