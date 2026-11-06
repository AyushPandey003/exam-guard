// Create or reset a staff account:  node create-user.js <username> <password>
const { open } = require('./store');
const [, , username, password] = process.argv;
if (!username || !password || password.length < 12) {
  console.error('usage: node create-user.js <username> <password (12+ chars)>');
  process.exit(1);
}
open(process.env.DB_PATH || __dirname + '/examguard.db').setUser(username, password);
console.log(`staff user '${username}' saved`);
