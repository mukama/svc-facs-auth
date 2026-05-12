'use strict'

module.exports = ({ max = 1000, maxAge = 0 } = {}) => {
  const store = new Map()

  return {
    get: (key) => {
      if (!store.has(key)) return undefined
      const value = store.get(key)
      store.delete(key)
      store.set(key, value)
      return value
    },
    set: (key, value) => {
      if (store.has(key)) store.delete(key)
      store.set(key, value)
      while (store.size > max) {
        const oldest = store.keys().next().value
        store.delete(oldest)
      }
    },
    remove: (key) => { store.delete(key) },
    peek: (key) => store.get(key),
    cache: {
      maxAge,
      get size () { return store.size }
    }
  }
}
