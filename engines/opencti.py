import requests

# Disable SSL warnings in case of proxies like Zscaler which break SSL...
requests.packages.urllib3.disable_warnings()

def query_opencti(observable, API_KEY, OPENCTI_URL, PROXIES):
    """
    Queries the OpenCTI API for information about a given observable.
    Args:
        observable (str): The observable to check.
        api_key (str): The API key for authentication.
        proxy (dict): The proxy settings.
    Returns:
        dict: A dictionary containing the response data.
        None: If the response does not contain the expected data.
    Raises:
        requests.exceptions.RequestException: If there is an issue with the network request.
        ValueError: If the response cannot be parsed as JSON.
    """
    try:
        # URL for the OpenCTI API
        url = f"{OPENCTI_URL}/graphql"
        
        # Headers including the API key
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
        
        # GraphQL query
        query = """
        query SearchStixCoreObjectsLinesPaginationQuery(
          $types: [String]
          $search: String
          $count: Int!
          $cursor: ID
          $orderBy: StixCoreObjectsOrdering
          $orderMode: OrderingMode
          $filters: FilterGroup
        ) {
          globalSearch(types: $types, search: $search, first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters) {
            edges {
              node {
                id
                entity_type
                created_at
                createdBy {
                  name
                  id
                }
                creators {
                  id
                  name
                }
                objectMarking {
                  id
                  definition_type
                  definition
                  x_opencti_order
                  x_opencti_color
                }
              }
              cursor
            }
            pageInfo {
              endCursor
              hasNextPage
              globalCount
            }
          }
        }
        """
        
        # Filter by date desc and take the first 100 results
        variables = {
            "count": 100,
            "orderMode": "desc",
            "orderBy": "created_at",
            "filters": {
                "mode": "and",
                "filters": [
                    {
                        "key": "entity_type",
                        "values": ["Stix-Core-Object"],
                        "operator": "eq",
                        "mode": "or"
                    }
                ],
                "filterGroups": []
            },
            "search": observable
        }
        
        # Payload for the POST request
        payload = {
            "id": "SearchStixCoreObjectsLinesPaginationQuery",
            "query": query,
            "variables": variables
        }
        
        # Make the POST request to the API
        response = requests.post(url, headers=headers, json=payload, proxies=PROXIES, verify=False)
        
        # Parse the JSON response
        data = response.json()
        
        # Check if the response contains the expected data
        if 'data' in data and 'globalSearch' in data['data']:
            entity_counts = {}
            edges = data['data']['globalSearch']['edges']
            for edge in edges:
                entity_type = edge['node']['entity_type']
                if entity_type in entity_counts:
                    entity_counts[entity_type] += 1
                else:
                    entity_counts[entity_type] = 1
            global_count = data['data']['globalSearch']['pageInfo']['globalCount']
            
            search_link = f"{OPENCTI_URL}/dashboard/search/knowledge/{observable}"
            return {"entity_counts": entity_counts, "global_count": global_count, "search_link": search_link}
    
    except Exception as e:
        print(e)
        # Always return None in case of failure
    return None