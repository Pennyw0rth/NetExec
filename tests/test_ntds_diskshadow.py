import os
from unittest.mock import MagicMock
from nxc.helpers.misc import CATEGORY
from nxc.modules.ntds_diskshadow import NXCModule


def test_module_attributes():
    """Verify module metadata complies with NetExec specifications."""
    assert NXCModule.name == "ntds_diskshadow"
    assert NXCModule.supported_protocols == ["smb"]
    assert NXCModule.category == CATEGORY.CREDENTIAL_DUMPING
    assert "DiskShadow" in NXCModule.description


def test_module_options_defaults():
    """Verify default module options."""
    mod = NXCModule()
    context = MagicMock()
    mod.options(context, {})

    assert mod.drive_letter == "Z"
    assert mod.cleanup is True
    assert os.path.exists(mod.dir_result)
    assert "nxc_ntds_" in mod.dir_result


def test_module_options_custom():
    """Verify custom module options parsing."""
    mod = NXCModule()
    context = MagicMock()
    mod.options(context, {
        "DRIVE_LETTER": "X:",
        "CLEANUP": "false",
        "DIR_RESULT": "C:\\temp\\custom_dump"
    })

    assert mod.drive_letter == "X"
    assert mod.cleanup is False
    assert mod.dir_result.endswith("custom_dump")


def test_module_options_invalid_drive():
    """Verify invalid drive letter is rejected."""
    mod = NXCModule()
    context = MagicMock()
    res = mod.options(context, {"DRIVE_LETTER": "INVALID"})

    assert res is False
    context.log.fail.assert_called_once()


def test_on_login_without_privilege():
    """Verify module aborts cleanly if SeBackupPrivilege is absent."""
    mod = NXCModule()
    context = MagicMock()
    connection = MagicMock()
    mod.options(context, {})

    connection.execute.return_value = "Privilege Name    Description    State\nSeChangeNotifyPrivilege  Bypass  Enabled"
    mod.on_login(context, connection)

    context.log.fail.assert_called_with("User does not have SeBackupPrivilege. Aborting.")


def test_on_login_full_flow():
    """Verify execution flow when SeBackupPrivilege is present."""
    mod = NXCModule()
    context = MagicMock()
    connection = MagicMock()
    mod.options(context, {})

    # Mock whoami output with SeBackupPrivilege
    connection.execute.side_effect = [
        "Privilege Name    Description    State\nSeBackupPrivilege  Back up files  Enabled",  # whoami /priv
        "",  # write dsh script
        "The command completed successfully.",  # diskshadow
        "1 File copied",  # robocopy
        "",  # rename
        "The operation completed successfully.",  # reg save
        "",  # unexpose script
        "",  # diskshadow unexpose
        "",  # del unexpose script
        "",  # del metadata
        "",  # del dsh script
        "",  # del ntds temp
        "",  # del system temp
    ]

    mod.on_login(context, connection)

    # Verify key steps were reached
    context.log.success.assert_any_call("SeBackupPrivilege is Enabled")
    context.log.success.assert_any_call(f"Shadow copy exposed on {mod.drive_letter}:\\")
    context.log.success.assert_any_call("NTDS.dit downloaded successfully")
    context.log.success.assert_any_call("SYSTEM hive downloaded successfully")
    context.log.success.assert_any_call("Remote cleanup completed")
