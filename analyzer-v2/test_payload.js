// Extremely vulnerable file for final Pen-Testing validation.

const AWS_ACCESS_KEY = "AKIA1234567890ABCDEF";
const SUPER_SECRET = "super_secret_backdoor";

function testAPI() {
    axios.post("https://api.internal-corp.local/v1/auth/login", {
        user: "admin",
        pass: "password"
    });
}

function insecureLogin(user, pass) {
    if (pass == SUPER_SECRET) {
        eval("grantAccess()");
    }
}

document.getElementById('root').innerHTML = "<script>alert(1)</script>";

let x = Math.random();
