/* ************************************************** *
 * ******************** Constructor
 * ************************************************** */

var util = require('util'),
    mongoose = require('mongoose');

var MongoStream = function(uri, options) {
  var self = this;
  
  if(!uri) { uri = 'mongodb://localhost:27017' }
  if(!options) { options = {} }

  // Establish separate connection to mongoose. This is so the logs can be sent to different databases.
  self.connection = mongoose.createConnection(uri, options);

  self.connection.on('error', function(err) {
    console.log('MongoStream connection failed. \n%s', err);
  });

  self.connection.once('open', function() {
    if(options.debug) {
      console.log('MongoStream database opened');
    }

    // Define Log model. If no schema is passed it will use a not strict schema which will log everything in the JSON object.
    options.schemaName = options.schemaName || 'Log';
    options.schema = options.schema || new mongoose.Schema({}, {strict: false});

    self.model = self.connection.model(options.schemaName, options.schema);
  });
};

// Inherit from writable stream.
util.inherits(MongoStream, require('stream').Writable);

/* ************************************************** *
 * ******************** Methods
 * ************************************************** */

/**
 * Implements the stream write interface to be used with a logger.
 * @param {object} obj - A log record.
 */
MongoStream.prototype.write = function(obj) {
  // Parse the passed string to JSON.
  if(typeof obj === 'string') {
    try {
      var logRecord = JSON.parse(obj);
    } catch(e) {
      console.log('Failed to parse log object as JSON \n %s', e);
      return;
    }
  } else {
    throw new Error('Unexpected log record type. Make sure that the bunyan stream type is set to \'stream\'');
  }

  var mongooseLog = new this.model(logRecord);
  mongooseLog.save(function(err) {
    if(err) {
      console.log('Failed to save log: \n%s', err);
    }
  });
};

/* ************************************************** *
 * ******************** Exports
 * ************************************************** */

module.exports = MongoStream;
