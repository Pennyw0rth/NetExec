from time import sleep
from nxc.helpers.misc import gen_random_string


class JOBEXEC:
    def __init__(self, mssql):
        self.mssql = mssql
        self.mssql_conn = mssql.conn
        self.logger = mssql.logger
        self.job_name = f"nxc_mssql_{gen_random_string(10)}"
        self.backuped_options = {}
        self.assembly_hex = None

    def execute(self, command, get_output, args=None) -> str:

        check_if_server_agent_run_query = """
        SELECT *
        FROM sys.dm_server_services
        WHERE servicename LIKE '%SQL Server Agent%'
        AND status = 4;
        """
        self.logger.debug(f"Running {check_if_server_agent_run_query}")
        rows = self.mssql_conn.sql_query(check_if_server_agent_run_query)
        if self.mssql_conn.lastError:
            self.logger.fail(f"Error executing jobexec: {self.mssql_conn.lastError}")
        if not rows or rows[0]["status"] != 4:
            self.logger.fail("SQL Server Agent not running.")
            return

        jobexec_query = f"""
        EXEC msdb.dbo.sp_add_job
            @job_name = '{self.job_name}';

        EXEC msdb.dbo.sp_add_jobstep
            @job_name = '{self.job_name}',
            @step_name = 'Run CMD',
            @subsystem = 'CMDEXEC',
            @command = '{command}';

        EXEC msdb.dbo.sp_add_jobserver
            @job_name = '{self.job_name}';

        EXEC msdb.dbo.sp_start_job
            @job_name = '{self.job_name}';
        """
        self.logger.debug(f"Running {jobexec_query}")
        self.mssql_conn.sql_query(jobexec_query)
        if self.mssql_conn.lastError:
            self.logger.fail(f"Error executing jobexec: {self.mssql_conn.lastError}")

        # Wait for the job for being executed
        wait_job_finished_query = f"""
        SELECT TOP 1 stop_execution_date
        FROM msdb.dbo.sysjobactivity a
        JOIN msdb.dbo.sysjobs j ON a.job_id = j.job_id
        WHERE j.name = '{self.job_name}'
        ORDER BY run_requested_date DESC;
        """
        self.logger.debug(f"Running {wait_job_finished_query}")
        for _ in range(10):
            rows = self.mssql_conn.sql_query(wait_job_finished_query)
            if rows and rows[0].get("stop_execution_date") != "NULL":
                break
            sleep(0.5)

        # Get output
        get_output_query = f"""
        SELECT TOP 1
            h.step_id,
            h.run_status,
            h.message,
            h.run_date,
            h.run_time
        FROM msdb.dbo.sysjobhistory h
        JOIN msdb.dbo.sysjobs j ON h.job_id = j.job_id
        WHERE j.name = '{self.job_name}'
        AND h.step_id > 0
        ORDER BY h.instance_id DESC;
        """
        self.logger.debug(f"Running {get_output_query}")
        result_rows = self.mssql_conn.sql_query(get_output_query)
        if self.mssql_conn.lastError:
            self.logger.fail(f"Error executing history retrieval: {self.mssql_conn.lastError}")

        cleanup_query = f"""
        EXEC msdb.dbo.sp_delete_job @job_name = '{self.job_name}';
        """
        self.logger.debug(f"Running {cleanup_query}")
        rows = self.mssql_conn.sql_query(cleanup_query)
        if self.mssql_conn.lastError:
            self.logger.fail(f"Error cleaning up: {self.mssql_conn.lastError}")

        return result_rows[0].get("message")
