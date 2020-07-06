/* eslint-disable */

var addon = require('bindings')('hello');

module.exports = {
    get_cmd() {
        return addon.get_cmd()
    }
}