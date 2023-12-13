import { defaultTo, find, juxt, path, pipe, prop, propEq } from 'ramda'

const URL_TAG = 'Url'
const TTL_TAG = 'Time-To-Live'
const SCHEDULER_TAG = 'Scheduler'

const findTagValue = (name) => pipe(
  defaultTo([]),
  find(propEq(name, 'name')),
  defaultTo({}),
  prop('value')
)

const findTransactionTags = pipe(
  defaultTo({}),
  prop('tags'),
  defaultTo([])
)

function gatewayWith ({ fetch, GATEWAY_URL }) {
  return async ({ query, variables }) => {
    return fetch(`${GATEWAY_URL}/graphql`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, variables })
    })
      .then((res) => res.json())
  }
}

export function loadProcessSchedulerWith ({ fetch, GATEWAY_URL }) {
  const gateway = gatewayWith({ fetch, GATEWAY_URL })
  const loadScheduler = loadSchedulerWith({ fetch, GATEWAY_URL })

  const GET_TRANSACTIONS_QUERY = `
    query GetTransactions ($transactionIds: [ID!]!) {
      transactions(ids: $transactionIds) {
        edges {
          node {
            tags {
              name
              value
            }
          }
        }
      }
    }
  `

  return async (process) => {
    return gateway({ query: GET_TRANSACTIONS_QUERY, variables: { transactionIds: [process] } })
      .then(path(['data', 'transactions', 'edges', '0', 'node']))
      .then(findTransactionTags)
      .then(findTagValue(SCHEDULER_TAG))
      .then((walletAddress) => {
        if (!walletAddress) throw new Error('No "Scheduler" tag found on process')
        return loadScheduler(walletAddress)
      })
  }
}

export function loadSchedulerWith ({ fetch, GATEWAY_URL }) {
  const gateway = gatewayWith({ fetch, GATEWAY_URL })

  const GET_SCHEDULER_LOCATION = `
    query GetSchedulerLocation ($owner: String!) {
      transactions (
        owners: [$owner]
        tags: [
          { name: "Data-Protocol", values: ["ao"] },
          { name: "Type", values: ["Scheduler-Location"] }
        ]
        # Only need the most recent Scheduler-Location
        sort: HEIGHT_DESC
        first: 1
      ) {
        edges {
          node {
            tags {
              name
              value
            }
          }
        }
      }
    }
  `

  return async (walletAddress) =>
    gateway({ query: GET_SCHEDULER_LOCATION, variables: { owner: walletAddress } })
      .then(path(['data', 'transactions', 'edges', '0', 'node']))
      .then(findTransactionTags)
      .then(juxt([
        findTagValue(URL_TAG),
        findTagValue(TTL_TAG)
      ]))
      .then(([url, ttl]) => {
        if (!url) throw new Error('No "Url" tag found on Scheduler-Location')
        if (!ttl) throw new Error('No "Time-To-Live" tag found on Scheduler-Location')
        return { url, ttl, owner: walletAddress }
      })
}
