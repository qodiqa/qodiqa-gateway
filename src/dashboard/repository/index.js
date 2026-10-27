'use strict';
const { InMemoryRepository } = require('./InMemoryRepository');
const store                  = require('../store');
module.exports = new InMemoryRepository(store);
