module.exports = function(dm, mongoose) {


  /* ************************************************** *
   * ******************** Global Variables
   * ************************************************** */

  var async, _;

  var config = dm.config,
    log = dm.log;

  var idAttributeName = '_id';

  /* ************************************************** *
   * ******************** Constructor & Inherit
   * ************************************************** */

  function MongooseAdapter() {
    this.mongoose = mongoose || require('mongoose');

    if(!async) {
      async = require('async');
    }

    if( ! _) {
      _ = require('lodash');
    }

    dm.DatabaseAdapter.call(this, config, log);
  }

  MongooseAdapter.prototype = dm.inherit(dm.DatabaseAdapter.prototype);


  /* ************************************************** *
   * ******************** Mongoose Adapter Methods
   * ************************************************** */

  MongooseAdapter.prototype.addItem = function(schemaName, item, cb) {
    var adapter = this;

    var Model = adapter.mongoose.model(schemaName);
    new Model(item).save(function(err, newItem) {
      if(err) {
        cb(err);
      } else {
        log.t("Added %s with id.", schemaName, newItem._id);
        cb(undefined, newItem);
      }
    });
  };

  MongooseAdapter.prototype.addItems = function(items, schemaName, cb) {
    var adapter = this;

    if(!_.isArray(items)) {
      items = [items];
    }

    async.each(items, function(item, next) {
      adapter.addItem(schemaName, item, next);
    }, cb);
  };

  MongooseAdapter.prototype.removeItem = function(schemaName, item, cb) {
    this.removeItemById(schemaName, item[idAttributeName], cb);
  };

  MongooseAdapter.prototype.removeItems = function(items, schemaName, cb) {
    if( ! _.isArray(items)) {
      items = [ items ];
    }

    var ids = [];
    for(var i = 0; i < items.length; i++) {
      ids.push(items[i][idAttributeName]);
    }

    this.removeItemsById(schemaName, ids, cb);
  };

  MongooseAdapter.prototype.removeItemsById = function(schemaName, ids, cb) {
    var adapter = this;

    if(!_.isArray(ids)) {
      ids = [ids];
    }

    async.each(ids, function (id, next) {
      adapter.removeItemById(schemaName, id, next)
    }, cb);
  };

  MongooseAdapter.prototype.removeItemById = function(schemaName, id, cb) {
    var adapter = this,
      Schema = adapter.mongoose.model(schemaName),
      query = {};

    query[idAttributeName] = id;

    Schema.findOne(query, function (err, data) {
      if (err) {
        cb(err);
      } else {
        if (data === undefined || data === null) {
          adapter.log.t("Schema %s with item id %s already removed.", schemaName, id);
          cb();
        } else {
          data.remove(function(err, removedData) {
            if(err) {
              return cb(err);
            }

            adapter.log.t("Schema %s with item id %s removed.", schemaName, data._id);
            cb();
          });
        }
      }
    });
  };


  /* ************************************************** *
   * ********************
   * ************************************************** */

  return new MongooseAdapter();
};