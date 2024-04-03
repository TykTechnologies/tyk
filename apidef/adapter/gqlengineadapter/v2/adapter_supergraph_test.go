package v2

const federationAccountsServiceSDL = `extend type Query {me: User} type User @key(fields: "id"){ id: ID! username: String!}`
const federationProductsServiceSDL = `extend type Query {topProducts(first: Int = 5): [Product]} type Product @key(fields: "upc") {upc: String! name: String! price: Int!}`
const federationReviewsServiceSDL = `type Review { body: String! author: User! @provides(fields: "username") product: Product! } extend type User @key(fields: "id") { id: ID! @external reviews: [Review] } extend type Product @key(fields: "upc") { upc: String! @external reviews: [Review] }`
const federationMergedSDL = `type Query { me: User topProducts(first: Int = 5): [Product] } type User { id: ID! username: String! reviews: [Review] } type Product { upc: String! name: String! price: Int! reviews: [Review] } type Review { body: String! author: User! product: Product! }`
