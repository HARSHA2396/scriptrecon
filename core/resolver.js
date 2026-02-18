const estraverse = require("estraverse");

function resolveBaseEndpoints(ast){

    const baseVars = {};
    const results = new Set();

    estraverse.traverse(ast, {

        enter(node){

            // Capture: const BASE = "https://..."
            if (
                node.type === "VariableDeclarator" &&
                node.init &&
                node.init.type === "Literal" &&
                typeof node.init.value === "string"
            ){
                baseVars[node.id.name] = node.init.value;
            }

            // Capture: fetch(BASE + "/path")
            if (
                node.type === "CallExpression" &&
                node.arguments &&
                node.arguments.length > 0
            ){
                const arg = node.arguments[0];

                if (
                    arg &&
                    arg.type === "BinaryExpression" &&
                    arg.operator === "+"
                ){
                    const left = arg.left;
                    const right = arg.right;

                    if (
                        left.type === "Identifier" &&
                        baseVars[left.name] &&
                        right.type === "Literal"
                    ){
                        const full = baseVars[left.name] + right.value;
                        results.add(full);
                    }
                }
            }
        }
    });

    if (results.size > 0){
        const { log } = require("../utils/logger");
        log("\n[Resolved Endpoints]", 'verbose');
        results.forEach(r => log(` ${r}`, 'verbose'));
    }
}

module.exports = resolveBaseEndpoints;
