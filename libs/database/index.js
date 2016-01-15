var Database = function(config, log) {
  this.config = config;
  this.log = log;
};

// Method to connect to a MongoDB database.
Database.prototype.connect = function(cb) {
  var mongoose = require('mongoose'),
      self = this;

  mongoose.connect(self.config.database.uri);
  mongoose.connection.on('error', function(err) {
    log.error(err);
  });
  mongoose.connection.once('open', function() {
    initializeDatabase(self, mongoose, function(err) {
      cb(err, mongoose);
    });
  });
};

var initializeDatabase = function(self, mongoose, cb) {
  // Check if we should initialize the database when connecting.
  if( ! self.config.database.initializeOnConnect) {
    cb();
  } else {
    // TODO: Add an admin user, roles, and etc. to the
    //       database, if they are not already there.
    cb();
  }
};

exports = module.exports = Database;
exports = Database;