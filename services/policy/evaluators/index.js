'use strict';

const REGISTRY = {
  REQUIRE_CONSENT: require('./requireConsent'),
  BLOCK_IP:        require('./blockIp'),
  TIME_WINDOW:     require('./timeWindow'),
  RATE_LIMIT:      require('./rateLimit'),
  DLP:             require('./dlp'),
  ABAC:            require('./abac'),
  BUDGET:          require('./budget'),
  CONTENT_RULE:    require('./contentRule'),
  ROUTING:         require('./routing'),
  DATA_RESIDENCY:  require('./dataResidency'),
  DATA_RETENTION:  require('./dataRetention'),
};

module.exports = REGISTRY;
