def add_user_bh(user, domain, logger, config):
    """Adds a user to the BloodHound graph database.

    Args:
    ----
        user (str or list): The username of the user or a list of user dictionaries.
        domain (str): The domain of the user.
        logger (Logger): The logger object for logging messages.
        config (ConfigParser): The configuration object for accessing BloodHound settings.

    Returns:
    -------
        None

    Raises:
    ------
        ApiException: If BloodHoundAPI is not available on the specified URI.
        AuthError: If the provided Neo4J credentials are not valid.
        ServiceUnavailable: If Neo4J is not available on the specified URI.
        Exception: If an unexpected error occurs with Neo4J.
        
    """
    users_owned = []
    if isinstance(user, str):
        users_owned.append({"username": user.upper(), "domain": domain.upper()})
    else:
        users_owned = user

    if config.get("BloodHoundAPI", "bh_enabled") != "False":
        logger.debug(f"Add to bloodhound: {users_owned}")
        from .bloodhoundAPI import BloodHoundAPI, ApiException

        api = BloodHoundAPI(url=config.get("BloodHoundAPI", "url"), token_id=config.get("BloodHoundAPI", "token_id"), token_key=config.get("BloodHoundAPI", "token_key"), logger=logger)
        try:
            for user_info in users_owned:
                # First,look for the domain in bloodhound
                domains = api.domains()
                logger.debug(f"Domains: {domains}")
                if any(item.get("name") == user_info["domain"] for item in domains):
                    _add_with_domain_api(user_info, user_info["domain"], api, logger)
                else:
                    _add_without_domain_api(user_info, api, logger)
        except ApiException as e:
            logger.fail(f"BloodHoundAPI error {e}.")
    elif config.get("BloodHound", "bh_enabled") != "False":
        # we do a conditional import here to avoid loading these if BH isn't enabled
        from neo4j import GraphDatabase
        from neo4j.exceptions import AuthError, ServiceUnavailable

        uri = f"bolt://{config.get('BloodHound', 'bh_uri')}:{config.get('BloodHound', 'bh_port')}"

        driver = GraphDatabase.driver(
            uri,
            auth=(
                config.get("BloodHound", "bh_user"),
                config.get("BloodHound", "bh_pass"),
            ),
            encrypted=False,
        )
        try:
            with driver.session().begin_transaction() as tx:
                for user_info in users_owned:
                    distinguished_name = "".join([f"DC={dc}," for dc in user_info["domain"].split(".")]).rstrip(",")
                    domain_query = tx.run(f"MATCH (d:Domain) WHERE d.distinguishedname STARTS WITH '{distinguished_name}' RETURN d").data()
                    if not domain_query:
                        logger.debug(f"Domain {user_info['domain']} not found in BloodHound. Falling back to domainless query.")
                        _add_without_domain(user_info, tx, logger)
                    else:
                        domain = domain_query[0]["d"].get("name")
                        _add_with_domain(user_info, domain, tx, logger)
        except AuthError:
            logger.fail(f"Provided Neo4J credentials ({config.get('BloodHound', 'bh_user')}:{config.get('BloodHound', 'bh_pass')}) are not valid.")
        except ServiceUnavailable:
            logger.fail(f"Neo4J does not seem to be available on {uri}.")
        except Exception as e:
            logger.fail(f"Unexpected error with Neo4J: {e}")
        finally:
            driver.close()




def _add_with_domain(user_info, domain, tx, logger):
    if user_info["username"][-1] == "$":
        user_owned = f"{user_info['username'][:-1]}.{domain}"
        account_type = "Computer"
    else:
        user_owned = f"{user_info['username']}@{domain}"
        account_type = "User"

    result = tx.run(f"MATCH (c:{account_type} {{name:'{user_owned}'}}) RETURN c").data()

    if len(result) == 0:
        logger.fail("Account not found in the BloodHound database.")
        return
    if result[0]["c"].get("owned") in (False, None):
        logger.debug(f"MATCH (c:{account_type} {{name:'{user_owned}'}}) SET c.owned=True RETURN c.name AS name")
        result = tx.run(f"MATCH (c:{account_type} {{name:'{user_owned}'}}) SET c.owned=True RETURN c.name AS name").data()[0]
        logger.highlight(f"Node {result['name']} successfully set as owned in BloodHound")


def _add_without_domain(user_info, tx, logger):
    if user_info["username"][-1] == "$":
        user_owned = user_info["username"][:-1]
        account_type = "Computer"
    else:
        user_owned = user_info["username"]
        account_type = "User"

    result = tx.run(f"MATCH (c:{account_type}) WHERE c.name STARTS WITH '{user_owned}' RETURN c").data()

    if len(result) == 0:
        logger.fail("Account not found in the BloodHound database.")
        return
    elif len(result) >= 2:
        logger.fail(f"Multiple accounts found with the name '{user_info['username']}' in the BloodHound database. Please specify the FQDN ex:domain.local")
        return
    elif result[0]["c"].get("owned") in (False, None):
        logger.debug(f"MATCH (c:{account_type} {{name:'{result[0]['c']['name']}'}}) SET c.owned=True RETURN c.name AS name")
        result = tx.run(f"MATCH (c:{account_type} {{name:'{result[0]['c']['name']}'}}) SET c.owned=True RETURN c.name AS name").data()[0]
        logger.highlight(f"Node {result['name']} successfully set as owned in BloodHound")

def _add_with_domain_api(user_info, domain, api, logger):
    if user_info["username"][-1] == "$":
        search = f"{user_info['username'][:-1]}.{domain}"
        logger.debug(f"Searching: {search}")
        result = api.search(search)
    else:
        search = f"{user_info['username']}@{domain}"
        logger.debug(f"Searching: {search}")
        result = api.search(search)

    if len(result) == 0:
        logger.fail("Account not found in the BloodHoundAPI database. {}")
        return
    logger.debug(f"Result from API {result}")
    logger.debug(f"Add to OWNED now: {search}")
    members = api.get_member_asset_groups(1, result[0]["objectid"])
    if len(members["members"]) < 1:
        api.add_to_asset_group(1, result[0]["objectid"])
        logger.highlight(f"Node {result[0]['name']} successfully set as owned in BloodHound")


def _add_without_domain_api(user_info, api, logger):
    if user_info["username"][-1] == "$":
        search = f"{user_info['username'][:-1]}"
        logger.debug(f"Searching: {search}")
        result = api.search(search)
    else:
        search = f"{user_info['username']}"
        logger.debug(f"Searching: {search}")
        result = api.search(search)

    if len(result) == 0:
        logger.fail("Account not found in the BloodHoundAPI database. {}")
        return
    elif len(result) >= 2:
        logger.fail(f"Multiple accounts found with the name '{user_info['username']}' in the BloodHound database. Please specify the FQDN ex:domain.local")
        return
    logger.debug(f"Result from API {result}")
    logger.debug(f"Add to OWNED now: {search}")
    members = api.get_member_asset_groups(1, result[0]["objectid"])
    if len(members["members"]) < 1:
        api.add_to_asset_group(1, result[0]["objectid"])
        logger.highlight(f"Node {result[0]['name']} successfully set as owned in BloodHound")
