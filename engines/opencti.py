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

      # Define the search link
      search_link = f"{OPENCTI_URL}/dashboard/search/knowledge/{observable}"
      
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
        
        # Find the most recent element and check if it's an Indicator
        first_element = edges[0]['node']
        first_id = first_element['id']
        latest_created_at = first_element['created_at']
        latest_indicator_link = f"{OPENCTI_URL}/dashboard/observations/indicators/{first_id}" if first_element['entity_type'] == "Indicator" else None

        # If the most recent element is not an Indicator, search for an Indicator in the data
        if first_element['entity_type'] != "Indicator":
          for edge in edges:
            if edge['node']['entity_type'] == "Indicator":
              first_element = edge['node']
              first_id = first_element['id']
              latest_created_at = first_element['created_at']
              latest_indicator_link = f"{OPENCTI_URL}/dashboard/observations/indicators/{first_id}"
              break

        # If the most recent element is an Indicator, query for its additional attributes
        x_opencti_score = None
        revoked = None
        valid_from = None
        valid_until = None
        confidence = None
        name = None
        if first_element['entity_type'] == "Indicator":
          additional_query = """
          query GetIndicator($id: String!) {
            indicator(id: $id) {
              name
              x_opencti_score
              revoked
              valid_from
              valid_until
              confidence
            }
          }
          """
          additional_variables = {"id": first_id}
          additional_payload = {
            "query": additional_query,
            "variables": additional_variables
          }
          additional_response = requests.post(url, headers=headers, json=additional_payload, proxies=PROXIES, verify=False)
          additional_data = additional_response.json()
          if 'data' in additional_data and 'indicator' in additional_data['data']:
            indicator_data = additional_data['data']['indicator']
            x_opencti_score = indicator_data.get('x_opencti_score')
            revoked = indicator_data.get('revoked')
            valid_from = indicator_data.get('valid_from')
            valid_until = indicator_data.get('valid_until')
            confidence = indicator_data.get('confidence')
            name = indicator_data.get('name')

        # Format dates to YYYY-MM-DD
        if valid_from:
          valid_from = valid_from.split("T")[0]
        if valid_until:
          valid_until = valid_until.split("T")[0]
        if latest_created_at:
          latest_created_at = latest_created_at.split("T")[0]  

        return {
            "entity_counts": entity_counts,
            "global_count": global_count,
            "search_link": search_link,
            "latest_created_at": latest_created_at,
            "latest_indicator_link": latest_indicator_link,
            "latest_indicator_name": name,
            "x_opencti_score": x_opencti_score,
            "revoked": revoked,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "confidence": confidence
        }
    except Exception as e:
      print(e)

    return None
    
