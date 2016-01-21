var util = require('util'),
    bunyan = require('bunyan'),
    MongoStream = require('bunyan-mongo-stream'),
    PrettySteam = require('bunyan-pretty-stream');

var Log = function (options) {
  if(!options) { options = {} }

  this.name = getDefaultValue(options.name, 'Log');
  
  this.databaseLog = getDefaultValue(options.databaseLog, false);

  // Define bunyan logging streams. https://github.com/trentm/node-bunyan#streams
  var streams = options.streams || [];

  // Default logging stream that pretty prints to console.
  streams.push({
    stream: new PrettySteam()
  });

  streams.push({
    stream: new MongoStream('mongodb://localhost:27017/seedio_local')
  });

  //this.requestLogger = require('express-bunyan-logger')({
  //  name: this.name + ' Requests',
  //  serializers: bunyan.stdSerializers,
  //  streams: loggingStreams});

  this.log = bunyan.createLogger({
    name: this.name,
    serializers: bunyan.stdSerializers,
    streams: streams});
};

/* ************************************************** *
 * ******************** Methods
 * ************************************************** */

Log.prototype.requestLogger = function() {
  return this.requestLog;
};

Log.prototype.info = function() {
  this.log.info.apply(this.log, arguments);
};

Log.prototype.debug = function() {
  this.log.debug.apply(this.log, arguments);
};

Log.prototype.trace = function() {
  this.log.trace.apply(this.log, arguments);
};

Log.prototype.error = function() {
  this.log.error.apply(this.log, arguments);
};

Log.prototype.warn = function() {
  this.log.warn.apply(this.log, arguments);
};

/* ************************************************** *
 * ******************** Helper Functions
 * ************************************************** */

function getDefaultValue(obj, objectDefault) {
  return (obj === undefined || obj === null) ? objectDefault : obj
}

function getBunyanLogLevel(options) {
  
}

/* ************************************************** *
 * ******************** Exports
 * ************************************************** */

module.exports = Log;