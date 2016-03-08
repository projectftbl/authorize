var _ = require('lodash');

var Authorizer = function(permissions) {
  if (this instanceof Authorizer === false) return new Authorizer(permissions);

  this.permissions = init(permissions);
};

Authorizer.rights = {
  Nothing : 0
, Create  : 1
, Read    : 2
, Update  : 4
, Destroy : 8
, Lookup  : 16
};

var r = Authorizer.rights;

Authorizer.permissions = {
  None        : r.Nothing
, Lookup      : r.Lookup
, ReadOnly    : r.Lookup | r.Read
, Editor      : r.Lookup | r.Read | r.Update
, FullAccess  : r.Lookup | r.Read | r.Update | r.Create | r.Destroy
};

var p = Authorizer.permissions;

var init = function(permissions) {
  if (permissions == null) return;

  if (_(permissions).isArray() === false) permissions = [ permissions ];

  var fromArray = function(permission) {
    return _(permission).isArray()
      ? { thing: permission[0], permission: permission[1] }
      : permission
  };

  permissions = _(permissions).map(fromArray);

  return _.chain(permissions)
    .pluck('thing')
    .uniq()
    .map(function(thing) {
      return {
        thing      : thing 
      , permission : combine(permissions, thing)
      };
    })
    .value();
};

Authorizer.prototype.fromRoles = function(roles) {
  return _.chain(roles)

  .map(function(role) {
    return _(role.permissions).map(function(permission) {
      return [ permission.thing, permission.permission ];
    });
  })

  .flatten(true)
  .value();
};

var combine = function(permissions, thing) {
  return _.chain(permissions)
    .filter(function(p) { return p.thing === thing; })
    .pluck('permission')
    .reduce(function(l, r) {
      return l | r;
    }, 0)
    .value();
};

Authorizer.prototype.can = function(thing, right) {
  if (right == null) { // permission as string, e.g. 'read thing'
    var parts = thing.split(' ');

    if (parts.length < 2) return false;

    var thing = parts[1]
      , right = r[parts[0].charAt(0).toUpperCase() + parts[0].substr(1)];
  }

  if (right == null) return false;

  var permissions = _(this.permissions).find(function(a) { return a.thing === thing; });

  if (permissions == null) return false;

  if (permissions.permission === p.None && right !== r.Nothing) return false;
  if (permissions.permission === p.None && right === r.Nothing) return true;

  return (permissions.permission | right) === permissions.permission;
};

module.exports = Authorizer;