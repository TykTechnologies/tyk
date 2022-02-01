# This document describes current batching solution

## Why do we need dataLoader ?

DataLoader provides solutions for next problems:

### 1. Batching 
   
Batching highly decrease number of network request to data sources.
   
Resolver tries to resolve array of Products ```[Product1, Product2, Product3]```:
   
**Before:**
   
_fetch 1:_
```json
 {
   "method":"POST",
   "url":"http://localhost:4003",
   "body":{
     "query": "query($representations: [_Any!]!){_entities(representations: $representations){... on Product {name}}}",
     "variables":{"representations":[{"upc":"top-1","__typename":"Product"}]
   }
 }
```
   
_fetch 2:_
```json
{
  "method":"POST",
  "url":"http://localhost:4003",
  "body":{
    "query":"query($representations: [_Any!]!){_entities(representations: $representations){... on Product {name}}}",
    "variables":{"representations":[{"upc":"top-2","__typename":"Product"}]}
  }
}
```
   
_fetch 3:_
```json
{
  "method":"POST",
  "url":"http://localhost:4003",
  "body":{
    "query":"query($representations: [_Any!]!){_entities(representations: $representations){... on Product {name}}}",
    "variables":{"representations":[{"upc":"top-3","__typename":"Product"}]}
  }
}
```

**After:**
   
_fetch 1:_
```json
{
  "method":"POST",
  "url":"http://localhost:4003",
  "body":{
    "query":"query($representations: [_Any!]!){_entities(representations: $representations){... on Product {name}}}",
    "variables":{
      "representations":[
        {"upc":"top-1","__typename":"Product"},
        {"upc":"top-2","__typename":"Product"},
        {"upc":"top-3","__typename":"Product"}
      ]
    }
  }
}
```

### 2. Request deduplication
    
It allows requesting data for only uniq arguments set 

Resolver tries to resolve array of Products ```[Product1, Product2, Product1, Product3, Product2]```:
    
**Batch without deduplication:**
   
_fetch:_
```json
{
  "method":"POST",
  "url":"http://localhost:4003",
  "body":{
    "query":"query($representations: [_Any!]!){_entities(representations: $representations){... on Product {name}}}",
    "variables": {
      "representations":[
        {"upc":"top-1","__typename":"Product"},
        {"upc":"top-2","__typename":"Product"},
        {"upc":"top-1","__typename":"Product"},
        {"upc":"top-3","__typename":"Product"},
        {"upc":"top-2","__typename":"Product"}
      ]
    }
  }
}
```

**Batch with deduplication:**

fetch:
```json
{
  "method":"POST",
  "url":"http://localhost:4003",
  "body":{
    "query": "query($representations: [_Any!]!){_entities(representations: $representations){... on Product {name}}}",
    "variables": {
      "representations":[
        {"upc":"top-1","__typename":"Product"},
        {"upc":"top-2","__typename":"Product"},
        {"upc":"top-3","__typename":"Product"}
      ]
    }
  }
}
```

## How does dataLoader work ?

- dataLoader is request scope object. For every new graphql request (or every new Subscription message) it's required to create a new dataloader.
- resolve.Context keeps dataLoader for current request.
- resolve.Context keeps last(parent) `lastFetchID` for current request
- resolve.Context keeps `responsePath`, it's an array of all object.Path/Array.Path since `lastFetchID`, 
  in case if node is Array additionally add to `responsePath` special symbol - `@` (e.g., [topProducts, @ ])
- current dataLoader implementation is based on synchronous resolve strategy.
- when Resolver tries to resolve fetch (SingleFetch/BatchFetch) for `fetchID`, dataLoader resolves fetch with `fetchID` for all siblings.
- in case SingleFetch dataLoaders (Load) concurrently resolve fetch for all siblings
- in case BatchFetch dataLoaders (LoadBatch) creates batch request for resolving fetches for all siblings
- for creating fetch input dataLoader selects from `lastFetchID` response data by `responsePath` (it's an array of all object.Path/Array.Path since `lastFetchID`)
   
**Example:** 

_Query :_
```
query { 
     topProducts { 
          reviews { 
              body
              author { 
                 username 
              } 
          } 
     } 
  }
```

   
   
```
                                                    |topProducts|                                               FetchID=0
                                                          |
                                                          |
                                                          |    
                       |---------------------------|Array of Products|--------------------|
                       |                                  |                               |
                       |                                  |                               |   
                  |Product A|                        |Product B|                      |Product C|                
                       |                                  |                               |  
                       |                                  |                               |    
     |----------|Array of Reviews|--------|        |Array of Reviews|       |-----|Array of Reviews|-----|      FetchID=1;LastFetchID=0;responsePath=[topProducts @]
     |                 |                  |               |                 |                            |  
     |                 |                  |               |                 |                            |
 |Review A1|      |Review A2|      |Review A3|         |Review B1|     |Review C1|                  |Review C2|
     |                 |                  |               |                 |                            |
     |                 |                  |               |                 |                            |
  |Author 1|       |Author 2|         |Author 3|       |Author 4|       |Author 5|                   |Author 6| FetchID=2;LastFetchID=1;responsePath=[reviews @ author]


```

   1. creates dataLoader
   1. resolve `topProducts`, fetch with `FetchID=0` is required, return an array of products
      * set `lastFetchID` as `0`, 
      * add `topProducts` to `responsePath`
      * save response with FetchID `0`
   1. enters `Array of Products` node, add `@` to the `responsePath`, no need to fetch
   1. enters `Product A` node, no need to fetch
   1. enters `Array of Reviews` node, fetch with `FetchID`= 1 is required
      * dataLoader gets response `{"topProducts": [{"upc": "top1", ...}, {"upc": "top2", ...}, {"upc": "top3", ...}]}` from `lastFetchID` (it has been saved in step 2) 
        and builds fetch input for all `Array of Reviews` siblings (`selectedDataForFetch` method is responsible for finding all siblings)
      * resolve all fetches from previous step (when fetch is SingleFetch - send N concurrent requests, when fetch is BatchFetch - compose all fetches to single Batch),
         Planner is responsible to choose which type of Fetch to use (e.g., for graphql datasource it makes sense to use BatchFetch for resolving Entity)
      * save response with FetchID `1`
      * reset `responsePath` and add `reviews` and `@` to `responsePath` (`responsePath` = `["reviews", "@"]`)
      * set `lastFetchID` as `1`
   1. enters `Review A1` node, no need to fetch
      * add `author` to `responsePath` (`responsePath` = `["reviews", "@", "author"]`)
   1. enters `Author A1` node, fetch with `FetchID`=2 is required (actually, it's the last step that leads to fetching)
      * dataLoader gets response `[{"reviews":[{review A1}, {review A2}, {review A3}]}, {"reviews": [{review B1}]}, {"reviews": [{review C1}, {review C2}]` from `lastFetchID` (it has been saved in step 5)
      and builds fetch input for all `Author 1` siblings
      * resolve all fetches from previous step (when fetch is SingleFetch - send N concurrent requests, when fetch is BatchFetch - compose all fetches to single Batch)
      * save response with FetchID `2`
      * reset `responsePath`
      * set `lastFetchID` as `2`
   1. enters `Review A2` nodes, no need to fetch 
   1. enters `Author A2` node, fetch with `FetchID=2` is required
      * dataLoader has already requested required data (it's saved with `FetchID=2`), it just gets second element from response for `FetchID=2`

   1. enters second `Array of Reviews` node, fetch with `FetchID`= 1 is required
      * dataLoader has already requested required data (it's saved with `FetchID=1`), it just gets second element from response for `FetchID=1`
