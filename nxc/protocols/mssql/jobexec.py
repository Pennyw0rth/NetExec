from time import sleep
from nxc.helpers.misc import gen_random_string


class JOBEXEC:
    def __init__(self, mssql):
        self.mssql = mssql
        self.mssql_conn = mssql.conn
        self.logger = mssql.logger
        self.job_name = f"nxc_mssql_{gen_random_string(10)}"
        self.output_file = f"C:\\Windows\\Temp\\{self.job_name}.txt"
        self.backuped_options = {}

    def execute(self, command, get_output, args=None) -> str:
        job_created = False
        job_finished = False
        output = ""

        try:

            escaped_command = command.replace("'", "''")
            escaped_output_file = self.output_file.replace("'", "''")

            # Run the command execution job
            jobexec_query = f"""
            EXEC msdb.dbo.sp_add_job
                @job_name = '{self.job_name}';

            EXEC msdb.dbo.sp_add_jobstep
                @job_name = '{self.job_name}',
                @step_name = 'Run CMD',
                @subsystem = 'CMDEXEC',
                @command = '{escaped_command}',
                @output_file_name = '{escaped_output_file}';

            EXEC msdb.dbo.sp_add_jobserver
                @job_name = '{self.job_name}';

            EXEC msdb.dbo.sp_start_job
                @job_name = '{self.job_name}';
            """
            job_created = True
            self.logger.debug(f"Running {jobexec_query}")
            self.mssql_conn.sql_query(jobexec_query)
            if self.mssql_conn.lastError:
                self.logger.fail(f"Error executing jobexec: {self.mssql_conn.lastError}")
                return ""

            # Wait for the command execution job to be finished
            wait_job_finished_query = f"""
            SELECT TOP 1
                a.start_execution_date,
                a.stop_execution_date,
                a.run_requested_date
            FROM msdb.dbo.sysjobactivity a
            JOIN msdb.dbo.sysjobs j ON a.job_id = j.job_id
            WHERE j.name = '{self.job_name}'
            AND a.session_id = (
                SELECT MAX(session_id)
                FROM msdb.dbo.syssessions
            )
            ORDER BY a.run_requested_date DESC;
            """

            self.logger.debug(f"Running {wait_job_finished_query}")

            for _ in range(self.mssql.args.get_output_tries):
                rows = self.mssql_conn.sql_query(wait_job_finished_query)

                if self.mssql_conn.lastError:
                    self.logger.fail(f"Error checking job status: {self.mssql_conn.lastError}")
                    return ""

                if rows and rows[0].get("stop_execution_date") is not None:
                    job_finished = True
                    break

                sleep(0.5)

            if not job_finished:
                self.logger.fail("Job execution timed out.")
                return ""

            # Check whether the command execution job succeeded
            check_job_status_query = f"""
            SELECT TOP 1
                run_status,
                message
            FROM msdb.dbo.sysjobhistory h
            JOIN msdb.dbo.sysjobs j ON h.job_id = j.job_id
            WHERE j.name = '{self.job_name}'
            AND h.step_id = 1
            ORDER BY h.instance_id DESC;
            """

            self.logger.debug(f"Running {check_job_status_query}")
            status_rows = self.mssql_conn.sql_query(check_job_status_query)

            if self.mssql_conn.lastError or not status_rows:
                self.logger.fail(f"Error retrieving job status: {self.mssql_conn.lastError}")
                return ""

            if status_rows[0]["run_status"] != 1:
                self.logger.fail(f"Command execution job failed: {status_rows[0]['message']}")
                return ""

            # Read the output file via OPENROWSET
            if get_output:
                read_output_query = f"""
                SELECT BulkColumn
                FROM OPENROWSET(
                    BULK '{escaped_output_file}',
                    SINGLE_NCLOB
                ) AS Output;
                """

                self.logger.debug(f"Running {read_output_query}")
                result_rows = self.mssql_conn.sql_query(read_output_query)

                if self.mssql_conn.lastError or not result_rows:
                    self.logger.fail(f"Error retrieving job output: {self.mssql_conn.lastError}")
                    return ""

                # Returns the output
                output = result_rows[0]["BulkColumn"] or ""

            return output

        finally:
            # Stop the command execution job if it is still running
            if job_created:
                check_job_activity_query = f"""
                SELECT TOP 1
                    a.start_execution_date,
                    a.stop_execution_date
                FROM msdb.dbo.sysjobactivity a
                JOIN msdb.dbo.sysjobs j ON a.job_id = j.job_id
                WHERE j.name = '{self.job_name}'
                AND a.session_id = (
                    SELECT MAX(session_id)
                    FROM msdb.dbo.syssessions
                )
                ORDER BY a.run_requested_date DESC;
                """

                self.logger.debug(f"Running {check_job_activity_query}")
                rows = self.mssql_conn.sql_query(check_job_activity_query)

                if not self.mssql_conn.lastError and rows:
                    if rows[0].get("start_execution_date") is not None and rows[0].get("stop_execution_date") is None:
                        stop_job_query = f"""
                        EXEC msdb.dbo.sp_stop_job
                            @job_name = '{self.job_name}';
                        """

                        self.logger.debug(f"Running {stop_job_query}")
                        self.mssql_conn.sql_query(stop_job_query)

                        if self.mssql_conn.lastError:
                            self.logger.fail(f"Error stopping execution job: {self.mssql_conn.lastError}")

                        else:
                            for _ in range(self.mssql.args.get_output_tries):
                                rows = self.mssql_conn.sql_query(check_job_activity_query)

                                if self.mssql_conn.lastError:
                                    break

                                if rows and rows[0].get("stop_execution_date") is not None:
                                    break

                                sleep(0.5)

                # Deletes the command execution job
                delete_job_query = f"""
                IF EXISTS (
                    SELECT 1 FROM msdb.dbo.sysjobs
                    WHERE name = '{self.job_name}'
                )
                    EXEC msdb.dbo.sp_delete_job @job_name = '{self.job_name}';
                """

                self.logger.debug(f"Running {delete_job_query}")
                self.mssql_conn.sql_query(delete_job_query)

                if self.mssql_conn.lastError:
                    self.logger.fail(f"Error deleting execution job: {self.mssql_conn.lastError}")
                    return

            # Launch a job that deletes the temporary file
            cleanup_job_name = f"{self.job_name}_cleanup"
            escaped_output_file = self.output_file.replace("'", "''")

            try:
                cleanup_query = f"""
                EXEC msdb.dbo.sp_add_job
                    @job_name = '{cleanup_job_name}';

                EXEC msdb.dbo.sp_add_jobstep
                    @job_name = '{cleanup_job_name}',
                    @step_name = 'Delete output file',
                    @subsystem = 'CMDEXEC',
                    @command = 'cmd.exe /c del /F /Q "{escaped_output_file}"';

                EXEC msdb.dbo.sp_add_jobserver
                    @job_name = '{cleanup_job_name}';

                EXEC msdb.dbo.sp_start_job
                    @job_name = '{cleanup_job_name}';
                """

                self.logger.debug(f"Running {cleanup_query}")
                self.mssql_conn.sql_query(cleanup_query)

                if self.mssql_conn.lastError:
                    self.logger.fail(f"Error creating cleanup job ({cleanup_job_name}): {self.mssql_conn.lastError}")

                else:
                    # Wait for the cleanup job to finish
                    wait_cleanup_query = f"""
                    SELECT TOP 1
                        a.start_execution_date,
                        a.stop_execution_date
                    FROM msdb.dbo.sysjobactivity a
                    JOIN msdb.dbo.sysjobs j ON a.job_id = j.job_id
                    WHERE j.name = '{cleanup_job_name}'
                    AND a.session_id = (
                        SELECT MAX(session_id)
                        FROM msdb.dbo.syssessions
                    )
                    ORDER BY a.run_requested_date DESC;
                    """

                    cleanup_finished = False

                    for _ in range(self.mssql.args.get_output_tries):
                        rows = self.mssql_conn.sql_query(wait_cleanup_query)

                        if self.mssql_conn.lastError:
                            self.logger.fail(f"Error checking cleanup job status: {self.mssql_conn.lastError}")
                            break

                        if rows and rows[0].get("stop_execution_date") is not None:
                            cleanup_finished = True
                            break

                        sleep(0.5)

                    if not cleanup_finished:
                        self.logger.fail("Cleanup job execution timed out.")

                        stop_cleanup_job_query = f"""
                        EXEC msdb.dbo.sp_stop_job
                            @job_name = '{cleanup_job_name}';
                        """

                        self.logger.debug(f"Running {stop_cleanup_job_query}")
                        self.mssql_conn.sql_query(stop_cleanup_job_query)

                        if self.mssql_conn.lastError:
                            self.logger.fail(f"Error stopping cleanup job: {self.mssql_conn.lastError}")

                        else:
                            for _ in range(self.mssql.args.get_output_tries):
                                rows = self.mssql_conn.sql_query(wait_cleanup_query)

                                if rows and rows[0].get("stop_execution_date") is not None:
                                    cleanup_finished = True
                                    break

                                sleep(0.5)

                    # Deletes the cleanup job
                    if cleanup_finished:
                        delete_cleanup_job_query = f"""
                        IF EXISTS (
                            SELECT 1 FROM msdb.dbo.sysjobs
                            WHERE name = '{cleanup_job_name}'
                        )
                            EXEC msdb.dbo.sp_delete_job @job_name = '{cleanup_job_name}';
                        """

                        self.mssql_conn.sql_query(delete_cleanup_job_query)

                        if self.mssql_conn.lastError:
                            self.logger.fail(f"Error deleting cleanup job: {self.mssql_conn.lastError}")

            except Exception as e:
                self.logger.fail(f"Error during cleanup: {e}")