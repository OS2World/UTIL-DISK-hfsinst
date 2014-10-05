/*:VRX         Main
*/
/*  Main
*/
Main:
/*  Process the arguments.
    Get the parent window.
*/
    parse source . calledAs .
    parent = ""
    argCount = arg()
    argOff = 0
    if( calledAs \= "COMMAND" )then do
        if argCount >= 1 then do
            parent = arg(1)
            argCount = argCount - 1
            argOff = 1
        end
    end; else do
        call VROptions 'ImplicitNames'
        call VROptions 'NoEchoQuit'
    end
    InitArgs.0 = argCount
    if( argCount > 0 )then do i = 1 to argCount
        InitArgs.i = arg( i + argOff )
    end
    drop calledAs argCount argOff

/*  Load the windows
*/
    call VRInit
    parse source . . spec
    _VREPrimaryWindowPath = ,
        VRParseFileName( spec, "dpn" ) || ".VRW"
    _VREPrimaryWindow = ,
        VRLoad( parent, _VREPrimaryWindowPath )
    drop parent spec
    if( _VREPrimaryWindow == "" )then do
        call VRMessage "", "Cannot load window:" VRError(), ,
            "Error!"
        _VREReturnValue = 32000
        signal _VRELeaveMain
    end

/*  Process events
*/
    call Init
    signal on halt
    do while( \ VRGet( _VREPrimaryWindow, "Shutdown" ) )
        _VREEvent = VREvent()
        interpret _VREEvent
    end
_VREHalt:
    _VREReturnValue = Fini()
    call VRDestroy _VREPrimaryWindow
_VRELeaveMain:
    call VRFini
exit _VREReturnValue

VRLoadSecondary:
    __vrlsWait = abbrev( 'WAIT', translate(arg(2)), 1 )
    if __vrlsWait then do
        call VRFlush
    end
    __vrlsHWnd = VRLoad( VRWindow(), VRWindowPath(), arg(1) )
    if __vrlsHWnd = '' then signal __vrlsDone
    if __vrlsWait \= 1 then signal __vrlsDone
    call VRSet __vrlsHWnd, 'WindowMode', 'Modal' 
    __vrlsTmp = __vrlsWindows.0
    if( DataType(__vrlsTmp) \= 'NUM' ) then do
        __vrlsTmp = 1
    end
    else do
        __vrlsTmp = __vrlsTmp + 1
    end
    __vrlsWindows.__vrlsTmp = VRWindow( __vrlsHWnd )
    __vrlsWindows.0 = __vrlsTmp
    do while( VRIsValidObject( VRWindow() ) = 1 )
        __vrlsEvent = VREvent()
        interpret __vrlsEvent
    end
    __vrlsTmp = __vrlsWindows.0
    __vrlsWindows.0 = __vrlsTmp - 1
    call VRWindow __vrlsWindows.__vrlsTmp 
    __vrlsHWnd = ''
__vrlsDone:
return __vrlsHWnd

/*:VRX         __VXREXX____APPENDS__
*/
__VXREXX____APPENDS__:
/*
*/
return
/*:VRX         CheckMode
*/
/*
 * Figure out if we are eligible to install the Local Security feature.
 * This requires that (a) HPFS386 has already been installed, and (b) LAN
 * Server is installed.
 */
CheckMode: PROCEDURE

    hpfs386 = 0
    lansrv  = 0

    /* See if SYSLEVEL.HFS exists and reports IP*8600 or higher.
     */
    product = SysBootDrive() || '\IBM386FS'
    syslvl  = product'\SYSLEVEL.HFS'
    IF STREAM( syslvl, 'C', 'QUERY EXISTS') \= '' THEN DO
        data   = CHARIN( syslvl, 1, CHARS( syslvl ))  
        offset = C2D( REVERSE( SUBSTR( data, 34, 4 ))) + 11
        PARSE VAR data 1 . =(offset) level +2
        IF level >= 86 THEN hpfs386 = 1
        CALL STREAM syslvl, 'C', 'CLOSE'
    END

    /* See if SYSLEVEL.SRV exists and reports IP*8600 or higher.
     */
    product = FindLS( SysBootDrive() ) || '\IBMLAN'
    syslvl  = product'\SYSLEVEL.SRV'
    IF STREAM( syslvl, 'C', 'QUERY EXISTS') \= '' THEN DO
        data   = CHARIN( syslvl, 1, CHARS( syslvl ))  
        offset = C2D( REVERSE( SUBSTR( data, 34, 4 ))) + 11
        PARSE VAR data 1 . =(offset) level +2
        IF level >= 86 THEN lansrv = 1
        CALL STREAM syslvl, 'C', 'CLOSE'
    END

    IF ( hpfs386 == 1 ) & ( lansrv == 1 ) THEN DO
        CALL VRSet 'CHK_SECURITY', 'Enabled', 1
        CALL VRSet 'CHK_SECURITY', 'Visible', 1
    END

RETURN 

/*:VRX         CHK_SECURITY_Click
*/
CHK_SECURITY_Click: 

    set = VRGet( 'CHK_SECURITY', 'Set')
    CALL VRSet 'RB_AUTOCACHE',    'Enabled', \set
    CALL VRSet 'RB_SPECIFYCACHE', 'Enabled', \set
    CALL VRSet 'SPB_CACHESIZE',   'Enabled', \set
    CALL VRSet 'RB_AUTOHEAP' ,    'Enabled', \set
    CALL VRSet 'RB_SPECIFYHEAP',  'Enabled', \set
    CALL VRSet 'SPB_MAXHEAP',     'Enabled', \set
    CALL VRSet 'CHK_LAZY',        'Enabled', \set
    CALL VRSet 'CHK_MAXAGE',      'Enabled', \set
    CALL VRSet 'SPB_MAXAGE',      'Enabled', \set
    CALL VRSet 'CHK_BUFFERIDLE',  'Enabled', \set
    CALL VRSet 'SPB_BUFFERIDLE',  'Enabled', \set
    CALL VRSet 'CHK_USEALLMEM',   'Enabled', \set
    CALL VRSet 'PB_DEFAULT',      'Enabled', \set
    CALL VRSet 'CHK_RAID',        'Enabled', \set
    DROP set

RETURN

/*:VRX         CreateRSP
*/
CreateRSP: PROCEDURE EXPOSE sel_fault sel_secure
    ARG instdrv, landrv, srcdrv

    /* Figure out where to put the response file.
     */
    rspdir = ''
    osdir  = VALUE('OSDIR',,'OS2ENVIRONMENT')
    IF osdir \= '' THEN DO
        CALL SysFileTree osdir'\install\rsp', 'dirs.', 'DO'
        IF dirs.0 > 0 THEN rspdir = dirs.1
    END
    IF rspdir == '' THEN DO
        CALL SysFileTree instdrv'\os2\install', 'dirs.', 'DO'
        IF dirs.0 > 0 THEN rspdir = dirs.1
    END
    IF rspdir == '' THEN rspdir = instdrv

    /* Read the selected settings.
     */
    sel_fault  = VRGet('CHK_RAID',       'Set'  )
    sel_secure = VRGet('CHK_SECURITY',   'Set'  )
    sel_cache  = VRGet('RB_AUTOCACHE',   'Set'  )
    cfg_cache  = VRGet('SPB_CACHESIZE',  'Value')
    sel_heap   = VRGet('RB_AUTOHEAP',    'Set'  )
    cfg_heap   = VRGet('SPB_MAXHEAP',    'Value')
    sel_lazy   = VRGet('CHK_LAZY',       'Set'  )
    sel_age    = VRGet('CHK_MAXAGE',     'Set'  )
    cfg_age    = VRGet('SPB_MAXAGE',     'Value')
    sel_idle   = VRGet('CHK_BUFFERIDLE', 'Set'  )
    cfg_idle   = VRGet('SPB_BUFFERIDLE', 'Value')
    IF VRGet('CHK_USEALLMEM', 'Set'  ) == 1 THEN
        cfg_mem = 'Yes'
    ELSE
        cfg_mem = 'No'

    /* Determine the response file name. 
     */
    IF sel_secure == 1 THEN
        rspfile = rspdir'\hpfs386s.rsp'
    ELSE
        rspfile = rspdir'\hpfs386.rsp'
    CALL SysFileTree rspfile, 'files.', 'FO',,'**---'
    IF files.0 > 0 THEN CALL VRDeleteFile rspfile

    /* Write the settings to the response file.
     */

    IF sel_secure == 1 THEN DO
        CALL LINEOUT rspfile, 'Install386HPFS.Selection           = 0'
        CALL LINEOUT rspfile, 'InstallFaultTolerance.Selection    = 0'
        CALL LINEOUT rspfile, 'InstallLocalSecurity.Selection     = 1'
        CALL LINEOUT rspfile, 'WkStaDeterminesCacheSize.Selection = 0'
        CALL LINEOUT rspfile, 'WkStaDeterminesHeapSize.Selection  = 0'
        CALL LINEOUT rspfile, 'ConfigLazyWrite.Selection          = 0'
        CALL LINEOUT rspfile, 'HPFS386_Top.MediaDrive             =' LEFT( srcdrv, 1 )
        CALL LINEOUT rspfile, 'HPFS386_Top.Landrv                 =' landrv
        CALL LINEOUT rspfile, 'HPFS386_Top.InstallDrive           =' instdrv
        CALL LINEOUT rspfile, 'HPFS386_Top.isIntegratedInstall    = NO'
    END
    ELSE DO
        CALL LINEOUT rspfile, 'Install386HPFS.Selection           = 1'
        CALL LINEOUT rspfile, 'InstallFaultTolerance.Selection    =' sel_fault
        CALL LINEOUT rspfile, 'InstallLocalSecurity.Selection     = 0'
        CALL LINEOUT rspfile, 'WkStaDeterminesCacheSize.Selection =' sel_cache
        CALL LINEOUT rspfile, 'WkStaDeterminesHeapSize.Selection  =' sel_heap
        CALL LINEOUT rspfile, 'ConfigLazyWrite.Selection          =' sel_lazy
/*
        IF sel_cache == 1 THEN
            CALL LINEOUT rspfile, 'HPFS386_Top.Config386Cache         = 0'
        ELSE
*/
        IF sel_cache == 0 THEN
            CALL LINEOUT rspfile, 'HPFS386_Top.Config386Cache         =' cfg_cache
/*
        IF sel_heap == 1 THEN
            CALL LINEOUT rspfile, 'HPFS386_Top.ConfigHeap             = 0'
        ELSE
*/
        IF sel_heap == 0 THEN
            CALL LINEOUT rspfile, 'HPFS386_Top.ConfigHeap             =' cfg_heap
        IF sel_idle == 1 THEN
            CALL LINEOUT rspfile, 'HPFS386_Top.ConfigMinBufferIdle    =' cfg_idle
        IF sel_age  == 1 THEN
            CALL LINEOUT rspfile, 'HPFS386_Top.ConfigMaxCacheAge      =' cfg_age
        CALL LINEOUT rspfile, 'HPFS386_Top.ConfigUseAllMem        =' cfg_mem
        CALL LINEOUT rspfile, 'HPFS386_Top.MediaDrive             =' LEFT( srcdrv, 1 )
        CALL LINEOUT rspfile, 'HPFS386_Top.Landrv                 =' landrv
        CALL LINEOUT rspfile, 'HPFS386_Top.InstallDrive           =' instdrv
        CALL LINEOUT rspfile, 'HPFS386_Top.isIntegratedInstall    = NO'

        CALL LINEOUT rspfile, 'Install386HPFS.AsciiFile=('
        CALL LINEOUT rspfile, '    FileName={BootDrive}\CONFIG.SYS'
        CALL LINEOUT rspfile, '    SearchLine=^^RUN={Landrive}\\IBMLAN\\NETPROG\\CACHE386.EXE'
        CALL LINEOUT rspfile, '    NewLine=RUN={Landrive}\IBMLAN\NETPROG\CACHE386.EXE'
        CALL LINEOUT rspfile, '    AddAfterLine=^^ifs='
        CALL LINEOUT rspfile, '    SearchFound=2'
        CALL LINEOUT rspfile, '    SearchNotFound=4'
        CALL LINEOUT rspfile, ')'
        CALL LINEOUT rspfile, 'Install386HPFS.AsciiFile=('
        CALL LINEOUT rspfile, '    FileName={BootDrive}\CONFIG.SYS'
        CALL LINEOUT rspfile, '    SearchLine=^^EARLYMEMINIT=TRUE'
        CALL LINEOUT rspfile, '    NewLine=REM EARLYMEMINIT=TRUE'
        CALL LINEOUT rspfile, '    SrcLineOcc=2'
        CALL LINEOUT rspfile, '    SearchNotFound=8'
        CALL LINEOUT rspfile, ')'

    END
    CALL STREAM  rspfile, 'C', 'CLOSE'

RETURN rspfile

/*:VRX         FindLS
*/
FindLS: PROCEDURE
    ARG bootdrv

    PARSE VALUE SysIni( bootdrv'\IBMLVL.INI', 'IBM_LS', 'PATH') WITH ibmlan '00'x
    landrv = FILESPEC('DRIVE', ibmlan )
    IF landrv == '' THEN landrv = bootdrv

RETURN landrv
/*:VRX         Fini
*/
Fini:
    window = VRWindow()
    call VRSet window, "Visible", 0
    drop window
return 0

/*:VRX         Halt
*/
Halt:
    signal _VREHalt
return

/*:VRX         Init
*/
Init:
    CALL VRSet 'Console', 'WindowListTitle', ''

    IF RxFuncQuery('SysDriveMap') == 1 THEN DO
        CALL RxFuncAdd 'SysLoadFuncs', 'REXXUTIL', 'SysLoadFuncs'
        CALL SysLoadFuncs
    END

    window = VRWindow()

    CALL SetDefaults        /* Set reasonable default configuration values */
    CALL PopulateSource     /* Populate the 'source' drive combo-box       */
    CALL CheckMode          /* Decide whether Local Security is an option  */

    call VRMethod window, "CenterWindow"
    call VRSet window, "Visible", 1
    call VRMethod window, "Activate"
    drop window

RETURN

/*:VRX         PB_CANCEL_Click
*/
PB_CANCEL_Click: 
    CALL Quit
return

/*:VRX         PB_DEFAULT_Click
*/
PB_DEFAULT_Click: 
    CALL SetDefaults
RETURN

/*:VRX         PB_HELP_Click
*/
PB_HELP_Click: 
    CALL VRMethod 'WN_MAIN', 'InvokeHelp'
RETURN

/*:VRX         PB_INSTALL_Click
*/
PB_INSTALL_Click: 

    buttons.0 = 2
    buttons.1 = 'Yes'
    buttons.2 = 'No'
    ok = VRMessage( VRWindow(), 'Proceed with the installation?', 'Please Confirm', 'Q', 'buttons.', 1, 2 )
    IF ok \= 1 THEN RETURN

    instdrv  = SysBootDrive()

    ok = SysFileSearch('EARLYMEMINIT=TRUE', instdrv'\CONFIG.SYS', 'matches.')
    IF \ok & matches.0 > 0 THEN DO
        buttons.0 = 2
        buttons.1 = 'OK'
        buttons.2 = 'Cancel'
        ok = VRMessage( VRWindow(), 'The setting EARLYMEMINIT=TRUE appears to be set, which may cause problems.  If you continue with the installation, this setting will be disabled automatically.', 'Please Note', 'W', 'buttons.', 1, 2 )
        IF ok \= 1 THEN RETURN
    END

    srcdrv   = VRGet('CB_SOURCE', 'Value')
    landrv   = FindLS( instdrv )
    response = CreateRSP( instdrv, landrv, srcdrv )
    result   = RunInstall( response, instdrv, srcdrv )

    IF ( result == '00') | ( result == 'FE') | ( result == 'FF') THEN CALL Quit

RETURN

/*:VRX         PopulateSource
*/
PopulateSource: PROCEDURE 

    map = SysDriveMap()
    cddrv = 0
    DO i = 1 TO WORDS( map )

        /* 
         * Populate the 'source' dropdown with the list of available drives.
         */

        drv = WORD( map, i )
        CALL VRMethod 'CB_SOURCE', 'AddString', drv

        /*
         * Now try to guess which is the CD-ROM drive where the HPFS386 install 
         * files are located.  If a drive has the correct volume label for the 
         * HPFS386 installation CD, use that.  Otherwise, the first drive whose 
         * filesystem is either 'CDFS' or undefined will be our default.
         */

        fs  = SysFileSystemType( drv )
        PARSE VALUE SysDriveInfo( drv ) WITH . . . lbl
        IF STRIP( lbl ) == 'HPFS386' THEN cddrv = i
        ELSE IF ( cddrv == 0 ) & ( fs == 'CDFS') THEN cddrv = i
        ELSE IF ( cddrv == 0 ) & ( fs == '')     THEN cddrv = i

    END

    IF cddrv == 0 THEN cddrv = 1
    CALL VRSet 'CB_SOURCE', 'Selected', cddrv

RETURN

/*:VRX         Quit
*/
Quit:
    window = VRWindow()
    call VRSet window, "Shutdown", 1
    drop window
return

/*:VRX         RunInstall
*/
RunInstall: PROCEDURE EXPOSE sel_fault sel_secure
    ARG response, instdrv, source

    /* Figure out which language to install.
     */
    langvar = TRANSLATE( VALUE('LANG',,'OS2ENVIRONMENT'))
    SELECT
        WHEN langvar == 'JA_JP' THEN lang = 'JP'
        WHEN langvar == 'ZH_CN' THEN lang = 'CX'
        WHEN langvar == 'ZH_TW' THEN lang = 'TW'
        OTHERWISE                    lang = LEFT( langvar, 2 )
    END

    logs = VALUE('LOGFILES',,'OS2ENVIRONMENT')
    IF logs == '' THEN logs = instdrv

    log1      = logs'\hpfs386.l1'
    log2      = logs'\hpfs386.l2'
    prodfiles = source'\'lang'\HPFS386'
    proddef   = prodfiles'\FS386.RSP'

    /* Make sure the source files exist.
     */
    IF STREAM( proddef, 'C', 'QUERY EXISTS') == '' THEN DO
        message.0 = 5
        message.1 = 'The installation files ('prodfiles') could not be located.'
        message.2 = ''
        message.3 = 'Please insert the HPFS386 installation CD, or check the specified source drive.'
        message.4 = ''
        message.5 = 'Then try again.'
        CALL VRMessageStem VRWindow(), 'message.', 'CD Required', 'E'
        DROP message.
        RETURN '01'
    END

    CALL VRSet 'WN_MAIN', 'Visible', 0

    instlcmd = '@clifi /a:c /r:'proddef '/l1:'log1 '/l2:'log2 '/s:'prodfiles '/b:'instdrv '/r2:'response
    ADDRESS CMD instlcmd
    result  = D2X( rc, 4 )
    cidcode = LEFT( result, 2 ) 

    IF ( cidcode == '00') | ( cidcode == 'FE') | (cidcode == 'FF') THEN DO

        /* Post-installation tasks.
         */
        CALL SysMoveObject '<FI_HPFS386_UNINSTALL>', '<WP_ASDUNINSTFOLDER>'

        /* Display the success message.
         */
        message.0 = 3
        IF cidcode == '00' THEN
            message.1 = 'The installation completed successfully.' 
        ELSE
            message.1 = 'The installation completed successfully.  Please shut down and reboot the system.' 
        message.2 = ''
        message.3 = 'NOTE: CHKDSK may run automatically on the next system boot.  This is normal if HPFS386 was not previously installed.'
        CALL VRMessageStem VRWindow(), 'message.', 'Installation Complete  [0x'result']', 'I'
        DROP message.

        IF sel_fault == 1 THEN DO
            CALL VRMessage VRWindow(), 'To configure Fault Tolerance, run the ''Fault Tolerance Setup'' program (located in the System Setup folder) after rebooting.', 'Note', 'I'
        END

    END
    ELSE DO
        CALL VRMessage VRWindow(), 'The installation was not successful.  The return code is: 0x'result, 'CID Error 0x'result, 'E'
        CALL VRSet 'WN_MAIN', 'Visible', 1
    END

RETURN cidcode

/*:VRX         SetDefaults
*/
SetDefaults: PROCEDURE

    CALL VRSet 'RB_SPECIFYCACHE', 'Set', 1
    CALL VRSet 'RB_SPECIFYHEAP',  'Set', 1
    CALL VRSet 'CHK_LAZY',        'Set', 1
    CALL VRSet 'CHK_MAXAGE',      'Set', 1
    CALL VRSet 'CHK_BUFFERIDLE',  'Set', 1
    CALL VRSet 'CHK_USEALLMEM',   'Set', 1

    CALL VRSet 'SPB_CACHESIZE',  'Value', 32768
    CALL VRSet 'SPB_MAXHEAP',    'Value', 32768
    CALL VRSet 'SPB_MAXAGE',     'Value', 5000
    CALL VRSet 'SPB_BUFFERIDLE', 'Value', 500

RETURN

/*:VRX         SPB_BUFFERIDLE_LostFocus
*/
SPB_BUFFERIDLE_LostFocus: 
    val = VRGet('SPB_BUFFERIDLE', 'Value')
RETURN

/*:VRX         SPB_CACHESIZE_LostFocus
*/
SPB_CACHESIZE_LostFocus: 
    val = VRGet('SPB_CACHESIZE', 'Value')
RETURN

/*:VRX         SPB_MAXAGE_LostFocus
*/
SPB_MAXAGE_LostFocus: 
    val = VRGet('SPB_MAXAGE', 'Value')
RETURN

/*:VRX         SPB_MAXHEAP_LostFocus
*/
SPB_MAXHEAP_LostFocus: 
    val = VRGet('SPB_MAXHEAP', 'Value')
RETURN

/*:VRX         WN_MAIN_Close
*/
WN_MAIN_Close:
    call Quit
return

