import ts from 'typescript';

export interface AgentToolInfo {
  name: string;
  description: string;
  hasAuthCheck: boolean;
  line: number;
}

export class AIAgentAnalyzer {
  constructor() {}

  analyze(sourceFile: ts.SourceFile): AgentToolInfo[] {
    const tools: AgentToolInfo[] = [];

    const visit = (node: ts.Node) => {
      // Find objects defining tools/functions
      if (ts.isObjectLiteralExpression(node)) {
        const text = node.getText(sourceFile);
        if (/(tool|function|agent|assistant|description)/i.test(text) && /(name|description)/i.test(text)) {
          let toolName = '';
          let toolDesc = '';
          
          for (const prop of node.properties) {
            if (ts.isPropertyAssignment(prop)) {
              const name = prop.name.getText(sourceFile);
              if (name === 'name' && ts.isStringLiteral(prop.initializer)) {
                toolName = prop.initializer.text;
              } else if (name === 'description' && ts.isStringLiteral(prop.initializer)) {
                toolDesc = prop.initializer.text;
              }
            }
          }

          if (toolName) {
            // Verify if the object block or tool body contains auth checks
            const cleanText = text.replace(/\/\/.*|\/\*[\s\S]*?\*\//g, '');
            const hasAuthCheck = 
              cleanText.includes('auth') ||
              cleanText.includes('session') ||
              cleanText.includes('checkPermission') ||
              cleanText.includes('userId') ||
              cleanText.includes('role');

            const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
            tools.push({
              name: toolName,
              description: toolDesc,
              hasAuthCheck,
              line
            });
          }
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return tools;
  }
}
