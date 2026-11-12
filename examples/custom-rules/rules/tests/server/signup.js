// Test cases for no-logging-request-body.yaml (Express style)
const logger = require('./logger')

module.exports = (app) => {
  app.post('/signup', (req, res) => {
    // ruleid: myapp-logs-request-body
    logger.info('signup', req.body)
    // ok: myapp-logs-request-body
    logger.info('signup for', req.body.email ? 'an email user' : 'unknown')
    res.sendStatus(201)
  })
}
