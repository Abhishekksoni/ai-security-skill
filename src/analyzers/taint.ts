import ts from 'typescript';

export type TrustLevel = 'untrusted' | 'trusted' | 'derived' | 'unknown';

export interface TaintFlow {
  source: string;
  flow: string[];
  sink: string;
  line: number;
}

export class TaintAnalyzer {
  private taintMap = new Map<string, { level: TrustLevel; flow: string[] }>();
  private findings: TaintFlow[] = [];

  constructor() {}

  analyze(sourceFile: ts.SourceFile): TaintFlow[] {
    this.taintMap.clear();
    this.findings = [];

    const visit = (node: ts.Node) => {
      // 1. Detect Variable Declarations (Taint source and propagation)
      if (ts.isVariableDeclaration(node) && node.initializer) {
        const initText = node.initializer.getText(sourceFile);
        
        // Check if source is untrusted
        const isUntrustedSource = 
          /req\.(body|query|params|json)/.test(initText) ||
          /request\.(body|query|params|json)/.test(initText) ||
          /await\s+(request|req)\.json\(/.test(initText) ||
          /URLSearchParams|FormData/.test(initText);

        // Check if source is trusted (e.g. database query)
        const isTrustedSource = 
          /db\.\w+\.find/.test(initText) ||
          /prisma\.\w+\.find/.test(initText) ||
          /conn\.query/.test(initText) ||
          /await\s+getProduct/.test(initText);

        // Process destructuring: const { price, quantity } = ...
        if (ts.isObjectBindingPattern(node.name)) {
          for (const element of node.name.elements) {
            if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
              const varName = element.name.text;
              if (isUntrustedSource) {
                this.taintMap.set(varName, {
                  level: 'untrusted',
                  flow: [initText, varName]
                });
              } else if (isTrustedSource) {
                this.taintMap.set(varName, {
                  level: 'trusted',
                  flow: [initText, varName]
                });
              }
            }
          }
        } 
        // Process normal binding: const price = req.body.price
        else if (ts.isIdentifier(node.name)) {
          const varName = node.name.text;
          if (isUntrustedSource) {
            this.taintMap.set(varName, {
              level: 'untrusted',
              flow: [initText, varName]
            });
          } else if (isTrustedSource) {
            this.taintMap.set(varName, {
              level: 'trusted',
              flow: [initText, varName]
            });
          } else {
            // Taint propagation: const amount = price * quantity
            const referencedVars = this.findIdentifiers(node.initializer);
            let hasUntrusted = false;
            let untrustedFlow: string[] = [];
            
            for (const ref of referencedVars) {
              const info = this.taintMap.get(ref);
              if (info && info.level === 'untrusted') {
                hasUntrusted = true;
                untrustedFlow = [...info.flow];
                break;
              }
            }

            const hasTrusted = referencedVars.some(ref => {
              const info = this.taintMap.get(ref);
              return info && info.level === 'trusted';
            });

            if (hasTrusted) {
              this.taintMap.set(varName, {
                level: 'trusted',
                flow: [varName]
              });
            } else if (hasUntrusted) {
              this.taintMap.set(varName, {
                level: 'untrusted',
                flow: [...untrustedFlow, varName]
              });
            }
          }
        }
      }

      // 2. Detect Call Expressions (Taint sinks)
      if (ts.isCallExpression(node)) {
        const exprText = node.expression.getText(sourceFile);
        
        // Match payment creation sinks
        const isPaymentSink = 
          /stripe\.paymentIntents\.create/.test(exprText) ||
          /stripe\.checkout\.sessions\.create/.test(exprText) ||
          /paypal\.orders\.create/.test(exprText) ||
          /paymentIntents\.create/.test(exprText);

        if (isPaymentSink) {
          const firstArg = node.arguments[0];
          if (firstArg && ts.isObjectLiteralExpression(firstArg)) {
            // Inspect properties to see if a tainted variable reaches the amount/price field
            for (const prop of firstArg.properties) {
              let propName = '';
              let referenced: string[] = [];
              let valText = '';

              if (ts.isPropertyAssignment(prop)) {
                propName = prop.name.getText(sourceFile);
                if (/^(amount|price|value|total)$/.test(propName)) {
                  valText = prop.initializer.getText(sourceFile);
                  referenced = this.findIdentifiers(prop.initializer);
                }
              } else if (ts.isShorthandPropertyAssignment(prop)) {
                propName = prop.name.getText(sourceFile);
                if (/^(amount|price|value|total)$/.test(propName)) {
                  valText = prop.name.text;
                  referenced = [prop.name.text];
                }
              }

              if (propName && referenced.length > 0) {
                for (const ref of referenced) {
                  const info = this.taintMap.get(ref);
                  if (info && info.level === 'untrusted') {
                    const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
                    this.findings.push({
                      source: info.flow[0],
                      flow: [...info.flow, `${exprText}({ ${propName}: ${valText} })`],
                      sink: `${exprText}(...)`,
                      line
                    });
                    break;
                  }
                }
              }
            }
          }
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return this.findings;
  }

  private findIdentifiers(node: ts.Node): string[] {
    const ids: string[] = [];
    const visit = (n: ts.Node) => {
      if (ts.isIdentifier(n)) {
        ids.push(n.text);
      }
      ts.forEachChild(n, visit);
    };
    visit(node);
    return ids;
  }
}
