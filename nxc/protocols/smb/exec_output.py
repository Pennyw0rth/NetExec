from time import monotonic, sleep


def get_output_file(conn, share, filename, callback, tries, logger, method, first_read_delay=0.1):
    """Read the output file of an executed command, then delete it.

    Most commands finish within a few hundred ms, so the file is read every 0.1s during the first 0.4s
    (these quick reads don't count against --get-output-tries), then every 1s.
    """
    quick_until = monotonic() + 0.4
    sleep(first_read_delay)
    attempt = 1
    while True:
        try:
            logger.info(f"Attempting to read {share}\\{filename}")
            conn.getFile(share, filename, callback)
            break
        except Exception as e:
            if monotonic() < quick_until and ("STATUS_SHARING_VIOLATION" in str(e) or "STATUS_OBJECT_NAME_NOT_FOUND" in str(e)):
                sleep(0.1)
            elif attempt >= tries:
                logger.fail(f"{method}: Could not retrieve output file, it may have been detected by AV. Please increase the number of tries with the option '--get-output-tries'. If it is still failing, try the 'wmi' protocol or another exec method")
                break
            elif "STATUS_BAD_NETWORK_NAME" in str(e):
                logger.fail(f"{method}: Getting the output file failed - target has blocked access to the share: {share} (but the command may have executed!)")
                break
            elif "STATUS_VIRUS_INFECTED" in str(e):
                logger.fail("Command did not run because a virus was detected")
                break
            # When executing PowerShell and the command is still running, we get a sharing violation
            # We can use that information to wait longer than if the file is not found (probably av or something)
            elif "STATUS_SHARING_VIOLATION" in str(e):
                logger.info(f"File {share}\\{filename} is still in use with {tries - attempt} tries left, retrying...")
                attempt += 1
                sleep(1)
            elif "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                logger.info(f"File {share}\\{filename} not found with {tries - attempt} tries left, deducting 10 tries and retrying...")
                attempt += 10
                sleep(1)
            else:
                logger.debug(f"Exception when trying to read output file: {e!s}. {tries - attempt} tries left, retrying...")
                attempt += 1
                sleep(1)

    try:
        logger.debug(f"Deleting file {share}\\{filename}")
        conn.deleteFile(share, filename)
    except Exception as e:
        logger.debug(f"Could not delete {share}\\{filename}: {e}")
