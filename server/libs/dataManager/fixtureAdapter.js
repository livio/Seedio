var _;

var FixtureAdapter = function(name, dm, config, log) {
  this.name = name;
  this.dm = dm;
  this.config = config;
  this.log = log;
  _ = require("lodash");
};

FixtureAdapter.prototype.insertAll = function(cb) {
  this.dm.addItems(this.name, this.getAll(), cb);
};

FixtureAdapter.prototype.deleteAll = function(cb) {
  this.dm.removeItems(this.name, this.getAllAndNew(), cb);
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