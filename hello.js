/* eslint-disable */

var addon = require('bindings')('hello');

module.export = {
    get_cmd() {
        return addon.get_cmd()
    }
}