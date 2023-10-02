import bodyParser from 'body-parser'
import cors from 'cors'

import { readState } from '../domain/index.js'
import errors from './errors/index.js'

function injectDomain (req, _res, next) {
  req.domain = {}
  req.domain.readState = readState
  next()
}

const mountMiddlewares = (app) => [
  cors(),
  bodyParser.json(),
  bodyParser.urlencoded({ extended: false }),
  injectDomain,
  errors
].reduce(
  (app, middleware) => app.use(middleware),
  app
)

export default mountMiddlewares