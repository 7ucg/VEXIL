import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import generate from '@babel/generator';
import * as t from '@babel/types';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const babelCore = require('@babel/core');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const babelPluginClasses = require('@babel/plugin-transform-classes');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const babelPluginArrows = require('@babel/plugin-transform-arrow-functions');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const babelPluginDestructuring = require('@babel/plugin-transform-destructuring');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const babelPluginTemplateLiterals = require('@babel/plugin-transform-template-literals');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const babelPluginAsyncToGenerator = require('@babel/plugin-transform-async-to-generator');
// eslint-disable-next-line @typescript-eslint/no-require-imports
const babelPluginRegenerator = require('@babel/plugin-transform-regenerator');

// Inline plugin: converts ArrayPattern/ObjectPattern in function params to
// a named param + destructuring assignment at the top of the function body.
// transform-destructuring handles var/const but not function params, so we do it here.
function pluginDestructureParams({ types: bt }: { types: typeof t }) {
  let uid = 0;
  return {
    visitor: {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      'Function'(path: any) {
        const newParams: t.Identifier[] = [];
        const prepend: t.VariableDeclaration[] = [];
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        for (const param of path.node.params as any[]) {
          if (bt.isArrayPattern(param) || bt.isObjectPattern(param)) {
            const id = bt.identifier(`_dp${uid++}`);
            prepend.push(bt.variableDeclaration('var', [bt.variableDeclarator(param, id)]));
            newParams.push(id);
          } else {
            newParams.push(param);
          }
        }
        if (prepend.length > 0) {
          path.node.params = newParams;
          if (!bt.isBlockStatement(path.node.body)) {
            path.node.body = bt.blockStatement([bt.returnStatement(path.node.body)]);
          }
          path.node.body.body.unshift(...prepend);
        }
      }
    }
  };
}

export interface Pass1Options {
  renameIdentifiers: boolean;
  encryptStrings: boolean;
  flattenControlFlow: boolean;
}

export interface Pass1Result {
  code: string;
  astJson: string;  // Babel AST as JSON for Pass 2
}

// Alphanumeric name generator: a, b, ..., z, aa, ab, ...
function nameGen(): () => string {
  let n = 0;
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  return () => {
    let s = '', x = n++;
    do { s = chars[x % 26] + s; x = Math.floor(x / 26) - 1; } while (x >= 0);
    return '_0x' + s;  // prefix with _0x to look hex-ish
  };
}

export function pass1(source: string, opts: Pass1Options): Pass1Result {
  // Pre-transform: lower ES6+ constructs (classes, destructuring, template literals)
  // so the binary AST encoder only needs to handle ES5-level nodes.
  const lowered = babelCore.transformSync(source, {
    plugins: [
      babelPluginClasses,
      babelPluginArrows,
      pluginDestructureParams,
      babelPluginDestructuring,
      babelPluginTemplateLiterals,
      babelPluginAsyncToGenerator,
      babelPluginRegenerator,
    ],
    sourceType: 'unambiguous',
    configFile: false,
    babelrc: false,
  });
  const loweredSrc: string = lowered?.code ?? source;

  const ast = parser.parse(loweredSrc, {
    sourceType: 'module',
    plugins: ['typescript', 'classProperties', 'optionalChaining', 'nullishCoalescingOperator']
  });

  const nextName = nameGen();
  const renameMap = new Map<string, string>();  // original -> obf name

  if (opts.renameIdentifiers) {
    // First pass: collect all binding names (declarations)
    // We rename user-defined identifiers only, not globals
    traverse(ast, {
      Scope(path) {
        for (const [name, binding] of Object.entries(path.scope.bindings)) {
          if (!renameMap.has(name)) {
            renameMap.set(name, nextName());
          }
        }
      }
    });
    // Second pass: rename all identifier occurrences except non-computed property names
    traverse(ast, {
      Identifier(path) {
        const obf = renameMap.get(path.node.name);
        if (!obf) return;
        // Skip property names in non-computed member expressions (obj.prop — prop must stay)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const par = path.parent as any;
        if (path.parentPath.isMemberExpression() &&
            par.property === path.node &&
            !par.computed) return;
        // Skip keys in non-computed object literal properties, object methods, class methods
        if ((path.parentPath.isObjectProperty() || path.parentPath.isObjectMethod() ||
             path.parentPath.isClassMethod()) &&
            par.key === path.node && !par.computed) return;
        path.node.name = obf;
      }
    });
  }

  // String encryption: collect and replace string literals
  const encKey: number[] = Array.from({length: 16}, () => Math.floor(Math.random() * 256));
  const encStrings: number[][] = [];
  const strToIdx = new Map<string, number>();
  const decryptFnName = '_vxd';
  const strArrName = '_vxs';

  if (opts.encryptStrings) {
    traverse(ast, {
      StringLiteral(path) {
        // Don't encrypt import paths or require() arguments at top level
        if (path.parent && (t.isImportDeclaration(path.parent) ||
            (t.isCallExpression(path.parent) &&
             t.isIdentifier((path.parent as t.CallExpression).callee, {name: 'require'})))) {
          return;
        }
        const val = path.node.value;
        if (!strToIdx.has(val)) {
          const bytes = Array.from(new TextEncoder().encode(val));
          const enc = bytes.map((b, i) => b ^ encKey[i % 16]);
          strToIdx.set(val, encStrings.length);
          encStrings.push(enc);
        }
        const idx = strToIdx.get(val)!;
        const replacement = t.memberExpression(t.identifier(strArrName), t.numericLiteral(idx), true);
        // If this string is an object property key, make the property computed
        if (t.isObjectProperty(path.parent) && path.parent.key === path.node) {
          path.parent.computed = true;
          path.replaceWith(replacement);
        } else {
          path.replaceWith(replacement);
        }
      }
    });

    if (encStrings.length > 0) {
      // Prepend: const _vxs = (function(){...})()
      // The IIFE decrypts strings using XOR
      const keyArr = t.arrayExpression(encKey.map(b => t.numericLiteral(b)));
      const encArr = t.arrayExpression(
        encStrings.map(enc => t.arrayExpression(enc.map(b => t.numericLiteral(b))))
      );
      // _vxd decrypts a byte array: (b,i) => b ^ key[i % key.length]
      // _vxs = encStrings.map(enc => String.fromCharCode(...enc.map((b,i)=>b^key[i%16])))
      const decryptExpr = t.variableDeclaration('var', [
        t.variableDeclarator(
          t.identifier(strArrName),
          t.callExpression(
            t.memberExpression(encArr, t.identifier('map')),
            [t.arrowFunctionExpression(
              [t.identifier('e')],
              t.callExpression(
                t.memberExpression(t.identifier('String'), t.identifier('fromCharCode')),
                [t.spreadElement(
                  t.callExpression(
                    t.memberExpression(t.identifier('e'), t.identifier('map')),
                    [t.arrowFunctionExpression(
                      [t.identifier('b'), t.identifier('i')],
                      t.binaryExpression('^', t.identifier('b'),
                        t.memberExpression(keyArr,
                          t.binaryExpression('%', t.identifier('i'), t.numericLiteral(16)),
                          true))
                    )]
                  )
                )]
              )
            )]
          )
        )
      ]);
      (ast.program.body as t.Statement[]).unshift(decryptExpr);
    }
  }

  if (opts.flattenControlFlow) {
    // Flatten if/else chains into do { if(c){body;break;} if(c2){body;break;} else_body; } while(false)
    // The do-while(false) lets break exit cleanly without an infinite loop.
    traverse(ast, {
      IfStatement(path) {
        if (t.isIfStatement(path.parent)) return; // only outermost of each chain

        const stmts: t.Statement[] = [];
        let current: t.IfStatement | t.Statement | null = path.node;

        while (t.isIfStatement(current)) {
          const cons = t.blockStatement([
            ...extractStmts(current.consequent),
            t.breakStatement(),
          ]);
          stmts.push(t.ifStatement(current.test, cons, null));
          current = current.alternate ?? null;
        }
        if (current) {
          // else branch — no break needed, falls off end of do-while
          stmts.push(...extractStmts(current as t.Statement));
        }

        if (stmts.length > 1) {
          const doWhile = t.doWhileStatement(
            t.booleanLiteral(false),
            t.blockStatement(stmts)
          );
          path.replaceWith(doWhile);
        }
      }
    });
  }

  const { code } = generate(ast, { compact: true, comments: false });
  const astJson = JSON.stringify(ast);
  return { code, astJson };
}

function extractStmts(s: t.Statement): t.Statement[] {
  return t.isBlockStatement(s) ? s.body : [s];
}
