import ts from 'typescript';
import { TaintAnalyzer } from '../src/analyzers/taint.js';

const code = `
  export async function checkout(req: any) {
    const { price, quantity } = await req.json();
    const amount = price * quantity;
    await stripe.paymentIntents.create({
      amount,
      currency: 'usd'
    });
  }
`;

const sourceFile = ts.createSourceFile('checkout.ts', code, ts.ScriptTarget.Latest, true);

// Debug AST
const visit = (node: ts.Node) => {
  console.log('Node:', ts.SyntaxKind[node.kind], 'Text:', node.getText(sourceFile).slice(0, 40));
  ts.forEachChild(node, visit);
};
visit(sourceFile);

const analyzer = new TaintAnalyzer();
const flows = analyzer.analyze(sourceFile);
console.log('FLOWS:', flows);
