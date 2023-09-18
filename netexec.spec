# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(
    ['./nxc/netexec.py'],
     pathex=['./nxc'],
     binaries=[],
     datas=[
        ('./nxc/protocols', 'nxc/protocols'),
        ('./nxc/data', 'nxc/data'),
        ('./nxc/modules', 'nxc/modules')
     ],
     hiddenimports=[
         'nxc.protocols.mssql.mssqlexec',
         'nxc.connection',
         'impacket.examples.secretsdump',
         'impacket.dcerpc.v5.lsat',
         'impacket.dcerpc.v5.transport',
         'impacket.dcerpc.v5.lsad',
         'nxc.servers.smb',
         'nxc.protocols.smb.wmiexec',
         'nxc.protocols.smb.atexec',
         'nxc.protocols.smb.smbexec',
         'nxc.protocols.smb.mmcexec',
         'nxc.protocols.smb.smbspider',
         'nxc.protocols.smb.passpol',
         'paramiko',
         'pypsrp.client',
         'pywerview.cli.helpers',
         'impacket.tds',
         'impacket.version',
         'nxc.helpers.bash',
         'pylnk3',
         'lsassy',
         'win32timezone',
         'impacket.tds',
         'impacket.ldap.ldap',
         'impacket.tds'
         ],
     hookspath=['./nxc/.hooks'],
     runtime_hooks=[],
     excludes=[],
     win_no_prefer_redirects=False,
     win_private_assemblies=False,
     cipher=block_cipher,
     noarchive=False
 )
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='netexec',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    icon='./nxc/data/nxc.ico'
)
