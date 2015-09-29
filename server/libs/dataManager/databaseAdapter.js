/* ************************************************** *
 * ******************** Global Variables
 * ************************************************** */

var _;


/* ************************************************** *
 * ******************** Constructor
 * ************************************************** */

var DatabaseAdapter = function(config, log) {
  this.config = config;
  this.log = log;

  if( ! _) {
    _ = require("lodash");
  }
};


/* ************************************************** *
 * ******************** Transaction Methods
 * ************************************************** */

DatabaseAdapter.prototype.startTransaction = function(options, cb) {
  return cb(undefined, {});
};

DatabaseAdapter.prototype.endTransaction = function(transaction, cb) {
  return cb(undefined, transaction);
};

DatabaseAdapter.prototype.failedTransaction = function(transaction, err, cb) {
  return cb(undefined, transaction);
};


/* ************************************************** *
 * ******************** Database Methods
 * ************************************************** */

DatabaseAdapter.prototype.add = function(items, options, cb) {
  var database = this;
  database.startTransaction({}, function(err, transaction) {
    if(err) {
      cb(err, undefined, transaction);
    } else {
      database.addItems(items, options, function(err, results) {
        if(err) {
          database.failedTransaction(transaction, err, function(transactionError, transaction) {
            if(transactionError) {
              cb([err, transactionError], results, transaction);
            } else {
              cb(err, results, transaction);
            }
          });
        } else {
          database.endTransaction(transaction, function(err, transaction) {
            if(err) {
              cb(err, results, transaction);
            } else {
              cb(undefined, results, transaction);
            }
          });
        }
      });
    }
  });
};

DatabaseAdapter.prototype.addMethod = function(items, options) {
  var database = this;

  return function(cb) {
    database.add(items, options, cb);
  }
};

DatabaseAdapter.prototype.remove = function(items, options, cb) {
  var database = this;
  database.startTransaction({}, function(err, transaction) {
    if(err) {
      cb(err, undefined, transaction);
    } else {
      database.removeItems(items, options, function(err, results) {
        if(err) {
          database.failedTransaction(transaction, err, function(transactionError, transaction) {
            if(transactionError) {
              cb([err, transactionError], results, transaction);
            } else {
              cb(err, results, transaction);
            }
          });
        } else {
          database.endTransaction(transaction, function(err, transaction) {
            if(err) {
              cb(err, results, transaction);
            } else {
              cb(undefined, results, transaction);
            }
          });
        }
      });
    }
  });
};

DatabaseAdapter.prototype.removeMethod = function(items, options) {
  var database = this;

  return function(cb) {
    database.remove(items, options, cb);
  }
};


/* ************************************************** *
 * ******************** Expose API
 * ************************************************** */

exports = module.exports = DatabaseAdapter;
exports = DatabaseAdapter;