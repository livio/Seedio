var _;

var FixtureAdapter = function(name, dm, config, log) {
  this.name = name;
  this.db = dm.databaseAdapter;
  this.config = config;
  this.log = log;

  if( ! _) {
    _ = require("lodash");
  }
};

FixtureAdapter.prototype.insertAll = function(cb) {
  this.db.add(this.getAll(), this.name, cb);
};

FixtureAdapter.prototype.deleteAll = function(cb) {
  this.db.remove(this.getAllAndNew(), this.name, cb);
};

FixtureAdapter.prototype.findById = function(id, cb) {
  var items = this.getAll();
  for(var i = 0; i < items.length; i++) {
    if(items[i]._id == id) {
      return cb(undefined, items[i]);
    }
  }
  cb();
};

FixtureAdapter.prototype.populate = function(v, cb) {
  if( ! user) {
    cb();
  } else if(_.isObject(v)) {
    cb(undefined, v);
  } else if(_.isString(v)){
    this.findById(v, cb);
  } else {
    cb();
  }
};

FixtureAdapter.prototype.getNew = function() {
  return {};
};

FixtureAdapter.prototype.getAll = function() {
  return [];
};

FixtureAdapter.prototype.getAllAndNew = function() {
  var items = this.getAll();
  items.push(this.getNew());
  return items;
};

exports = module.exports = FixtureAdapter;
exports = FixtureAdapter;