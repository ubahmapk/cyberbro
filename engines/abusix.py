import querycontacts

def query_abusix(observable):
    """
    Queries the Abusix service for contact information related to the given observable.

    Args:
        observable (str): The observable (e.g., IP address, domain) to query.

    Returns:
        dict: A dictionary containing the abuse contact information if the query is successful.
        None: If an error occurs during the query.
    """
    try:
        abuse = querycontacts.ContactFinder().find(observable)
        return {"abuse": abuse[0]}
    except Exception:
        print("An error occurred while querying Abusix.")
    return None 