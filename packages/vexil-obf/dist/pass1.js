"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.pass1 = pass1;
const parser = __importStar(require("@babel/parser"));
const traverse_1 = __importDefault(require("@babel/traverse"));
const generator_1 = __importDefault(require("@babel/generator"));
const t = __importStar(require("@babel/types"));
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
function pluginDestructureParams({ types: bt }) {
    let uid = 0;
    return {
        visitor: {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            'Function'(path) {
                const newParams = [];
                const prepend = [];
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                for (const param of path.node.params) {
                    if (bt.isArrayPattern(param) || bt.isObjectPattern(param)) {
                        const id = bt.identifier(`_dp${uid++}`);
                        prepend.push(bt.variableDeclaration('var', [bt.variableDeclarator(param, id)]));
                        newParams.push(id);
                    }
                    else {
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
// Alphanumeric name generator: a, b, ..., z, aa, ab, ...
function nameGen() {
    let n = 0;
    const chars = 'abcdefghijklmnopqrstuvwxyz';
    return () => {
        let s = '', x = n++;
        do {
            s = chars[x % 26] + s;
            x = Math.floor(x / 26) - 1;
        } while (x >= 0);
        return '_0x' + s; // prefix with _0x to look hex-ish
    };
}
function pass1(source, opts) {
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
    const loweredSrc = lowered?.code ?? source;
    const ast = parser.parse(loweredSrc, {
        sourceType: 'module',
        plugins: ['typescript', 'classProperties', 'optionalChaining', 'nullishCoalescingOperator']
    });
    if (opts.poisonIdentifiers) {
        const poisonSrc = `if(false){` +
            `function validateLicense(token,sig){var _n='validateLicense';return sig.verify(token);}` +
            `function checkExpiry(date){var _n='checkExpiry';return Date.now()>date;}` +
            `function activateFeature(id){var _n='activateFeature';featureFlags[id]=true;}` +
            `function decryptPayload(key,ct){var _n='decryptPayload';return aes.decrypt(key,ct);}` +
            `function verifySignature(pub,msg,sig){var _n='verifySignature';return ed25519.verify(pub,msg,sig);}` +
            `function revokeSession(uid){var _n='revokeSession';sessions.delete(uid);}` +
            `function fetchLicenseServer(endpoint){var _n='fetchLicenseServer';return fetch(endpoint+'/v2/license');}` +
            `function hashPassword(pw,salt){var _n='hashPassword';return argon2.hash(pw,salt);}` +
            `function rotateKey(current){var _n='rotateKey';return deriveKey(current,entropy());}` +
            `function checkRateLimit(ip){var _n='checkRateLimit';return rateLimiter.check(ip);}` +
            `function authorizeRequest(token,scope){var _n='authorizeRequest';return jwt.verify(token,scope);}` +
            `function encryptResponse(data,key){var _n='encryptResponse';return aes.encrypt(data,key);}` +
            `function pruneExpiredTokens(){var _n='pruneExpiredTokens';tokenStore.prune(Date.now());}` +
            `function validateApiKey(key){var _n='validateApiKey';return apiKeys.has(key);}` +
            `function buildAuthHeader(token){var _n='buildAuthHeader';return 'Bearer '+token;}` +
            `}`;
        const poisonAst = parser.parse(poisonSrc, { sourceType: 'script' });
        const poisonStmt = poisonAst.program.body[0];
        ast.program.body.unshift(poisonStmt);
    }
    const nextName = nameGen();
    const renameMap = new Map(); // original -> obf name
    if (opts.renameIdentifiers) {
        // First pass: collect all binding names (declarations)
        // We rename user-defined identifiers only, not globals
        (0, traverse_1.default)(ast, {
            Scope(path) {
                for (const [name, binding] of Object.entries(path.scope.bindings)) {
                    if (!renameMap.has(name)) {
                        renameMap.set(name, nextName());
                    }
                }
            }
        });
        // Second pass: rename all identifier occurrences except non-computed property names
        (0, traverse_1.default)(ast, {
            Identifier(path) {
                const obf = renameMap.get(path.node.name);
                if (!obf)
                    return;
                // Skip property names in non-computed member expressions (obj.prop — prop must stay)
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                const par = path.parent;
                if (path.parentPath.isMemberExpression() &&
                    par.property === path.node &&
                    !par.computed)
                    return;
                // Skip keys in non-computed object literal properties, object methods, class methods
                if ((path.parentPath.isObjectProperty() || path.parentPath.isObjectMethod() ||
                    path.parentPath.isClassMethod()) &&
                    par.key === path.node && !par.computed)
                    return;
                path.node.name = obf;
            }
        });
    }
    // String encryption: collect and replace string literals
    const encKey = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
    const encStrings = [];
    const strToIdx = new Map();
    const decryptFnName = '_vxd';
    const strArrName = '_vxs';
    if (opts.encryptStrings) {
        (0, traverse_1.default)(ast, {
            StringLiteral(path) {
                // Don't encrypt import paths or require() arguments at top level
                if (path.parent && (t.isImportDeclaration(path.parent) ||
                    (t.isCallExpression(path.parent) &&
                        t.isIdentifier(path.parent.callee, { name: 'require' })))) {
                    return;
                }
                const val = path.node.value;
                if (!strToIdx.has(val)) {
                    const bytes = Array.from(new TextEncoder().encode(val));
                    const enc = bytes.map((b, i) => b ^ encKey[i % 16]);
                    strToIdx.set(val, encStrings.length);
                    encStrings.push(enc);
                }
                const idx = strToIdx.get(val);
                const replacement = t.memberExpression(t.identifier(strArrName), t.numericLiteral(idx), true);
                // If this string is an object property key, make the property computed
                if (t.isObjectProperty(path.parent) && path.parent.key === path.node) {
                    path.parent.computed = true;
                    path.replaceWith(replacement);
                }
                else {
                    path.replaceWith(replacement);
                }
            }
        });
        if (encStrings.length > 0) {
            // Prepend: const _vxs = (function(){...})()
            // The IIFE decrypts strings using XOR
            const keyArr = t.arrayExpression(encKey.map(b => t.numericLiteral(b)));
            const encArr = t.arrayExpression(encStrings.map(enc => t.arrayExpression(enc.map(b => t.numericLiteral(b)))));
            // _vxd decrypts a byte array: (b,i) => b ^ key[i % key.length]
            // _vxs = encStrings.map(enc => String.fromCharCode(...enc.map((b,i)=>b^key[i%16])))
            const decryptExpr = t.variableDeclaration('var', [
                t.variableDeclarator(t.identifier(strArrName), t.callExpression(t.memberExpression(encArr, t.identifier('map')), [t.arrowFunctionExpression([t.identifier('e')], t.callExpression(t.memberExpression(t.identifier('String'), t.identifier('fromCharCode')), [t.spreadElement(t.callExpression(t.memberExpression(t.identifier('e'), t.identifier('map')), [t.arrowFunctionExpression([t.identifier('b'), t.identifier('i')], t.binaryExpression('^', t.identifier('b'), t.memberExpression(keyArr, t.binaryExpression('%', t.identifier('i'), t.numericLiteral(16)), true)))]))]))]))
            ]);
            ast.program.body.unshift(decryptExpr);
        }
    }
    if (opts.flattenControlFlow) {
        // Flatten if/else chains into do { if(c){body;break;} if(c2){body;break;} else_body; } while(false)
        // The do-while(false) lets break exit cleanly without an infinite loop.
        (0, traverse_1.default)(ast, {
            IfStatement(path) {
                if (t.isIfStatement(path.parent))
                    return; // only outermost of each chain
                const stmts = [];
                let current = path.node;
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
                    stmts.push(...extractStmts(current));
                }
                if (stmts.length > 1) {
                    const doWhile = t.doWhileStatement(t.booleanLiteral(false), t.blockStatement(stmts));
                    path.replaceWith(doWhile);
                }
            }
        });
    }
    const { code } = (0, generator_1.default)(ast, { compact: true, comments: false, sourceMaps: false });
    const astJson = JSON.stringify(ast);
    return { code, astJson };
}
function extractStmts(s) {
    return t.isBlockStatement(s) ? s.body : [s];
}
