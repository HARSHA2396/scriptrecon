const { log } = require("../utils/logger");

function intel(code){
  const ips = code.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || [];
  if (ips.length > 0) {
    log("\n[IPs]", 'verbose');
    ips.forEach(i => log(` ${i}`, 'verbose'));
  }

  const emails = code.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || [];
  if (emails.length > 0) {
    log("\n[Emails]", 'verbose');
    emails.forEach(e => log(` ${e}`, 'verbose'));
  }
}

module.exports = intel;
