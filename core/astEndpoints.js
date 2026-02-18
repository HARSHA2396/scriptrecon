const estraverse = require("estraverse");
const { log } = require("../utils/logger");

function astEndpoints(ast) {

    const found = new Set();

    estraverse.traverse(ast, {
        enter(node) {

            // fetch("url")
            if (
                node.type === "CallExpression" &&
                node.callee.name === "fetch"
            ) {
                const arg = node.arguments[0];
                if (arg && arg.value) {
                    found.add(arg.value);
                }
            }

            // axios.get/post(...)
            if (
                node.type === "CallExpression" &&
                node.callee.type === "MemberExpression"
            ) {
                const obj = node.callee.object.name;
                const prop = node.callee.property.name;

                if (obj === "axios") {
                    const arg = node.arguments[0];
                    if (arg && arg.value) {
                        found.add(arg.value);
                    }
                }
            }
        }
    });

    if (found.size > 0) {
        log("\n[AST Endpoints]", 'verbose');
        found.forEach(e => log(` ${e}`, 'verbose'));
    }
}

module.exports = astEndpoints;
