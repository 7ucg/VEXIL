// Example 1: Module with config and helper function
const config = {
  host: 'db.internal',
  port: 5432,
  password: 'super-secret-hunter2',
  dbName: 'production',
};

function getConnectionString() {
  return 'postgresql://' + config.host + ':' + config.port + '/' + config.dbName;
}

function hashPassword(raw) {
  var result = '';
  for (var i = 0; i < raw.length; i++) {
    result += raw.charCodeAt(i).toString(16);
  }
  return result;
}

module.exports = { getConnectionString, hashPassword, config };
