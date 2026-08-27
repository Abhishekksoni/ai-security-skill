import test, { describe } from 'node:test';
import assert from 'node:assert/strict';
import ts from 'typescript';
import { TaintAnalyzer } from '../src/analyzers/taint.js';

describe('Taint Analysis Engine Tests', () => {
  const analyzer = new TaintAnalyzer();

  test('detects vulnerable client-controlled price flow', () => {
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
    const flows = analyzer.analyze(sourceFile);

    assert.strictEqual(flows.length, 1);
    assert.strictEqual(flows[0].sink, 'stripe.paymentIntents.create(...)');
    assert.match(flows[0].source, /req\.json\(\)/);
    assert.ok(flows[0].flow.includes('price'));
    assert.ok(flows[0].flow.includes('amount'));
  });

  test('accepts secure server-derived price flow without findings', () => {
    const code = `
      export async function checkout(req: any, db: any) {
        const { productId, quantity } = await req.json();
        const product = await db.product.findUnique({ where: { id: productId } });
        const amount = product.price * quantity;
        await stripe.paymentIntents.create({
          amount,
          currency: 'usd'
        });
      }
    `;
    const sourceFile = ts.createSourceFile('checkout.ts', code, ts.ScriptTarget.Latest, true);
    const flows = analyzer.analyze(sourceFile);

    assert.strictEqual(flows.length, 0);
  });

  test('tracks taint propagation through multiple steps', () => {
    const code = `
      export async function checkout(req: any) {
        const userPrice = req.body.price;
        const baseCost = userPrice;
        const total = baseCost * 1.08;
        await stripe.paymentIntents.create({
          amount: total
        });
      }
    `;
    const sourceFile = ts.createSourceFile('checkout.ts', code, ts.ScriptTarget.Latest, true);
    const flows = analyzer.analyze(sourceFile);

    assert.strictEqual(flows.length, 1);
    assert.strictEqual(flows[0].sink, 'stripe.paymentIntents.create(...)');
    assert.ok(flows[0].flow.includes('userPrice'));
    assert.ok(flows[0].flow.includes('baseCost'));
    assert.ok(flows[0].flow.includes('total'));
  });
});
