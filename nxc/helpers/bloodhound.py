#!/usr/bin/env python3


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
        AuthError: If the provided Neo4J credentials are not valid.
        ServiceUnavailable: If Neo4J is not available on the specified URI.
        Exception: If an unexpected error occurs with Neo4J.
    """
    users_owned = []
    if isinstance(user, str):
        users_owned.append({"username": user.upper(), "domain": domain.upper()})
    else:
        users_owned = user

    if config.get("BloodHound", "bh_enabled") != "False":
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
            with driver.session() as session, session.begin_transaction() as tx:
                for info in users_owned:
                    if info["username"][-1] == "$":
                        user_owned = info["username"][:-1] + "." + info["domain"]
                        account_type = "Computer"
                    else:
                        user_owned = info["username"] + "@" + info["domain"]
                        account_type = "User"

                    result = tx.run(f'MATCH (c:{account_type} {{name:"{user_owned}"}}) RETURN c')

                    if result.data()[0]["c"].get("owned") in (False, None):
                        logger.debug(f'MATCH (c:{account_type} {{name:"{user_owned}"}}) SET c.owned=True RETURN c.name AS name')
                        result = tx.run(f'MATCH (c:{account_type} {{name:"{user_owned}"}}) SET c.owned=True RETURN c.name AS name')
                        logger.highlight(f"Node {user_owned} successfully set as owned in BloodHound")
        except AuthError:
            logger.fail(f"Provided Neo4J credentials ({config.get('BloodHound', 'bh_user')}:{config.get('BloodHound', 'bh_pass')}) are not valid.")
            return
        except ServiceUnavailable:
            logger.fail(f"Neo4J does not seem to be available on {uri}.")
            return
        except Exception as e:
            logger.fail(f"Unexpected error with Neo4J: {e}")
            logger.fail("Account not found on the domain")
            return
        driver.close()
