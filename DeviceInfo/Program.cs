using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace DeviceInfo
{
    public static class Program
    {
        private static bool DumpDevice(IntPtr devs, uint devIndex, IntPtr /* PSP_DEVINFO_DATA */ devInfo)
        {
            int error;
            string label = GetDeviceStringProperty(devs, devInfo, DeviceProperty.FriendlyName);
            if (null != label) {
                while (label.EndsWith("\0")) {
                    label = (1 == label.Length) ? string.Empty : label.Substring(0, label.Length - 1);
                }
            }
            string description = GetDeviceStringProperty(devs, devInfo, DeviceProperty.Description);
            if (string.IsNullOrEmpty(label)) {
                label = description;
                description = null;
            }
            Output("------------------------------------");
            Output("{0} {1}", label ?? "UNKNOWN", description ?? string.Empty);
            Output("------------------------------------");
            int devInstance = Marshal.ReadInt32(devInfo, 20);
            int detailsLength = 560;
            IntPtr details = IntPtr.Zero;

            try {
                details = Marshal.AllocCoTaskMem(detailsLength);
                Marshal.WriteInt32(details, detailsLength);
                if (!SetupDiGetDeviceInfoListDetail(devs, details)) {
                    Marshal.FreeCoTaskMem(details);
                    details = IntPtr.Zero;
                    error = Marshal.GetLastWin32Error();
                    Output("\tNo details : error {0}", error);
                }

                if (!DumpDeviceWithInfo(devs, devInfo, label)) {
                    error = Marshal.GetLastWin32Error();
                    return false;
                }

                // Device class
                string className = GetDeviceStringProperty(devs, devInfo, DeviceProperty.Class);
                string classId = GetDeviceStringProperty(devs, devInfo, DeviceProperty.ClassGuid);
                if (string.IsNullOrEmpty(className) && string.IsNullOrEmpty(classId)) {
                    Output("\tNo class.");
                }
                else {
                    Output("\tClass {0} : {1}.", className ?? "NO NAME", classId ?? "NO ID");
                }

                DeviceStatus status = 0;
                Problem problem = 0;
                int nodeStatusCR = 0;
                if (null != details) {
                    nodeStatusCR = CM_Get_DevNode_Status_Ex(out status, out problem, devInstance,
                        0, IntPtr.Zero);
                }

                // Device status
                bool hasInfo = false;
                bool isPhantom = false;

                if (null != details) {
                    switch (nodeStatusCR) {
                        case 0 /* CR_SUCCESS */:
                            bool disabled = false;
                            if (0 != (DeviceStatus.HasProblem & status)) {
                                hasInfo = true;
                                if (Problem.CM_PROB_DISABLED == problem) {
                                    Output("\tDisabled");
                                    disabled = true;
                                }
                                else { Output("\tProblem : {0}", problem); }
                            }
                            if (!disabled) {
                                if (0 != (DeviceStatus.PrivateProblem & status)) {
                                    Output("\tPrivate problem.");
                                }
                                if (0 != (DeviceStatus.Started & status)) {
                                    Output("\tStarted.");
                                }
                                else if (!hasInfo) {
                                    Output("\tNot started.");
                                }
                            }
                            break;
                        case 0x0000000D: /* CR_NO_SUCH_DEVINST */
                        case 0x00000025: /* CR_NO_SUCH_VALUE */
                            Output("\tPhantom device.");
                            isPhantom = true;
                            break;
                        default:
                            Output("\tUnable to retrieve status. Error 0x{0:X8}", nodeStatusCR);
                            break;
                    }
                }

                // Device resources
                if ((null != details) && (0 == nodeStatusCR)) {
                    IntPtr config = IntPtr.Zero;
                    bool haveConfig = false;

                    // see if the device is running and what resources it might be using
                    if (0 == (status & DeviceStatus.HasProblem)) {
                        // If this device is running, does this devinst have a ALLOC log config?
                        if (0 == CM_Get_First_Log_Conf_Ex(out config, devInstance,
                            LogicalConfigurationRetrievalFlags.Allocated, IntPtr.Zero))
                        {
                            haveConfig = true;
                        }
                    }
                    if (!haveConfig) {
                        // If no config so far, does it have a FORCED log config?
                        // (note that technically these resources might be used by another device
                        // but is useful info to show)
                        if (0 == CM_Get_First_Log_Conf_Ex(out config, devInstance,
                            LogicalConfigurationRetrievalFlags.Forced, IntPtr.Zero))
                        {
                            haveConfig = true;
                        }
                    }

                    if (!haveConfig) {
                        // if there's a hardware-disabled problem, boot-config isn't valid
                        // otherwise use this if we don't have anything else
                        if ((0 == (DeviceStatus.HasProblem & status))
                            || (Problem.CM_PROB_HARDWARE_DISABLED != problem))
                        {
                            // Does it have a BOOT log config?
                            if (0 == CM_Get_First_Log_Conf_Ex(out config, devInstance,
                                LogicalConfigurationRetrievalFlags.Boot, IntPtr.Zero))
                            {
                                haveConfig = true;
                            }
                        }
                    }
                    if (!haveConfig) {
                        // if we don't have any configuration, display an apropriate message
                        Output((0 != (DeviceStatus.Started & status))
                            ? "\tNo resources."
                            : "\tNo reserved resources");
                    }
                    else {
                        Output((0 != (DeviceStatus.Started & status))
                            ? "\tResources :"
                            : "\tReserved resources :");
                        DumpDeviceResourcesOfType(IntPtr.Zero, config, ResourceType.All);
                        CM_Free_Log_Conf_Handle(config);
                    }
                }

                // Driver files
                //    DumpDeviceDriverFiles(Devs, DevInfo);

                // Device stack
                //    DumpDeviceStack(Devs, DevInfo);
                if (null != details) {
                    IntPtr hClassKey = InvalidHandleValue;

                    // we need device setup class, we can use the GUID in DevInfo
                    // note that this GUID is a snapshot, but works fine
                    // if DevInfo isn't old
                    // class upper/lower filters are in class registry
                    hClassKey = SetupDiOpenClassRegKeyEx(devInfo + sizeof(uint), KeyRead,
                        0x00000001, null, IntPtr.Zero);
                    List<string> filters;
                    RegistryKey classKey = (InvalidHandleValue == hClassKey)
                        ? null
                        : RegistryKey.FromHandle(new SafeRegistryHandle(hClassKey, true));

                    try {
                        if (null != classKey) {
                            // dump upper class filters if available
                            filters = GetRegistryMultiString(classKey, "UpperFilters");
                            if ((null != filters) && (0 < filters.Count)) {
                                Output("\tUpper filters :");
                                foreach(string filter in filters) {
                                    Output("\t\t{0}", filter);
                                }
                            }
                        }
                        filters = GetDeviceMultiString(devs, devInfo, DeviceProperty.UpperFilters);
                        if ((null != filters) && (0 < filters.Count)) {
                            // dump upper device filters
                            Output("\tDevice stack upper filters :");
                            foreach(string filter in filters) {
                                Output("\t\t{0}", filter);
                            }
                        }
                        string service = GetDeviceStringProperty(devs, devInfo, DeviceProperty.Service);
                        if (!string.IsNullOrEmpty(service)) {
                            Output("\tService : {0}", service);
                        }
                        else {
                            Output("\tNo service");
                        }
                        if (null != classKey) {
                            filters = GetRegistryMultiString(classKey, "LowerFilters");
                            if ((null != filters) && (null != filters[0])) {
                                // lower class filters
                                Output("\tClass lower filters:");
                                foreach(string item in filters) {
                                    Output("\t\t{0}", item);
                                }
                            }
                            else {
                                Output("\tNo class lower filters.");
                            }
                        }
                    }
                    finally {  if (null != classKey) { classKey.Close(); } }
                    filters = GetDeviceMultiString(devs, devInfo, DeviceProperty.LowerFilters);
                    if ((null != filters) && (null != filters[0])) {
                        Output("\tLower filters:");
                        foreach (string item in filters) {
                            Output("\t\t{0}", item);
                        }
                    }
                    else {
                        Output("\tNo lower filters.");
                    }
                }

                // Device hardware ids
                List<string> hwIdArray = GetDeviceMultiString(devs, devInfo, DeviceProperty.HardwareId);
                List<string> compatIdArray = GetDeviceMultiString(devs, devInfo, DeviceProperty.CompatibleIds);
                bool displayed = false;

                if ((null != hwIdArray) && (0 < hwIdArray.Count) && (null != hwIdArray[0])) {
                    displayed = true;
                    Output("\tHardware IDs:");
                    foreach(string item in hwIdArray) {
                        Output("\t\t{0}", item);
                    }
                }
                if ((null != compatIdArray) && (0 < compatIdArray.Count) && (null != compatIdArray[0])) {
                    displayed = true;
                    Output("\tCompatible IDs:");
                    foreach (string item in compatIdArray) {
                        Output("\t\t{0}", item);
                    }
                }
                if (!displayed) {
                    Output("\tNo hardware/compatible IDs found for this device.");
                }

                // Device driver nodes
                bool success = false;

                IntPtr deviceInstallParams = IntPtr.Zero; // SP_DEVINSTALL_PARAMS
                IntPtr driverInfoData = IntPtr.Zero; // SP_DRVINFO_DATA_W
                IntPtr driverInfoDetail = IntPtr.Zero; // SP_DRVINFO_DETAIL_DATA
                IntPtr driverInstallParams = IntPtr.Zero; // SP_DRVINSTALL_PARAMS

                try {
                    int deviceInstallParamsSize = 584;
                    deviceInstallParams = Marshal.AllocCoTaskMem(deviceInstallParamsSize);
                    Marshal.WriteInt32(deviceInstallParams, deviceInstallParamsSize);
                    int driverInfoDataSize = 1568;
                    driverInfoData = Marshal.AllocCoTaskMem(driverInfoDataSize);
                    Marshal.WriteInt32(driverInfoData, driverInfoDataSize);
                    int driverInfoDetailSize = 1584;
                    driverInfoDetail = Marshal.AllocCoTaskMem(driverInfoDetailSize);
                    Marshal.WriteInt32(driverInfoDetail, driverInfoDetailSize);
                    int driverInstallParamsSize = 32;
                    driverInstallParams = Marshal.AllocCoTaskMem(driverInstallParamsSize);
                    Marshal.WriteInt32(driverInstallParams, driverInstallParamsSize);

                    if (SetupDiGetDeviceInstallParams(devs, devInfo, deviceInstallParams)) {
                        // Set the flags that tell SetupDiBuildDriverInfoList to allow excluded drivers.
                        Marshal.WriteInt32(deviceInstallParams, 8,
                            Marshal.ReadInt32(deviceInstallParams, 8) | 0x800 /* DI_FLAGSEX_ALLOWEXCLUDEDDRVS */);
                        if (SetupDiSetDeviceInstallParams(devs, devInfo, deviceInstallParams)) {
                            // Now build a class driver list.
                            if (SetupDiBuildDriverInfoList(devs, devInfo, 0x02 /* SPDIT_COMPATDRIVER */)) {
                                // Enumerate all of the drivernodes.
                                int index = 0;
                                while (SetupDiEnumDriverInfo(devs, devInfo, 0x02 /* SPDIT_COMPATDRIVER */, index, driverInfoData)) {
                                    success = true;
                                    Output("\tDriver node #{0}", index);
                                    // get useful driver information
                                    int requiredSize;
                                    byte[] localBuffer;
                                    if (SetupDiGetDriverInfoDetail(devs, devInfo, driverInfoData, driverInfoDetail,
                                        driverInfoDetailSize, out requiredSize)
                                        || (122 /* ERROR_INSUFFICIENT_BUFFER */ == Marshal.GetLastWin32Error()))
                                    {
                                        Output("\tInf file is {0}",
                                            GetNativeString(260 /* MAX_PATH */, driverInfoDetail, 544));
                                        Output("\tInf section is {0}",
                                            GetNativeString(256 /* LINE_LEN */, driverInfoDetail, 32));
                                    }
                                    Output("\tDriver description is {0}",
                                            GetNativeString(256 /* LINE_LEN */, driverInfoDetail, 16));
                                    Output("\tManufacturer name is {0}",
                                            GetNativeString(256 /* LINE_LEN */, driverInfoDetail, 528));
                                    Output("\tProvider name is {0}",
                                            GetNativeString(256 /* LINE_LEN */, driverInfoDetail, 1040));

                                    //if (FileTimeToSystemTime(&driverInfoData.DriverDate, &SystemTime)) {
                                    //    if (GetDateFormat(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &SystemTime, NULL,
                                    //        Buffer, sizeof(Buffer) / sizeof(TCHAR)) != 0)
                                    //    {
                                    //        Output(MSG_DUMP_DRIVERNODE_DRIVERDATE, Buffer);
                                    //    }
                                    //}
                                    ulong version = (ulong)Marshal.ReadInt64(driverInfoDetail, 1560);
                                    Output("\tDriver version is {0}.{1}.{2}.{3}",
                                        (ushort)((version >> 48) & 0xFFFF), (ushort)((version >> 32) & 0xFFFF),
                                        (ushort)((version >> 16) & 0xFFFF), (ushort)((version) & 0xFFFF));
                                    if (SetupDiGetDriverInstallParams(devs, devInfo, driverInfoData, driverInstallParams)) {
                                        int driverInstallFlags = Marshal.ReadInt32(driverInstallParams, 8);
                                        Output("\tDriver node rank is {0}", Marshal.ReadInt32(driverInstallParams, 4));
                                        Output("\tDriver node flags are {0:X8}", driverInstallFlags);

                                        // Interesting flags to dump
                                        if (0 != (driverInstallFlags & 0x0400 /* DNF_OLD_INET_DRIVER*/)) {
                                            Output("\tInf came from the Internet");
                                        }
                                        if (0 != (driverInstallFlags & 0x0800 /* DNF_BAD_DRIVER*/)) {
                                            Output("\tDriver node is marked \"BAD\"");
                                        }
                                        // DNF_INF_IS_SIGNED is available since WinXP
                                        if (0 != (driverInstallFlags & 0x2000 /* DNF_INF_IS_SIGNED*/)) {
                                            Output("\tInf is digitally signed");
                                        }
                                        // DNF_OEM_F6_INF is only available since WinXP
                                        if (0 != (driverInstallFlags & 0x4000 /* DNF_OEM_F6_INF*/ )) {
                                            Output("\tInf was installed by using F6 during text mode setup");
                                        }
                                        // DNF_BASIC_DRIVER is only available since WinXP
                                        if (0 != (driverInstallFlags & 0x00010000 /* DNF_BASIC_DRIVER*/)) {
                                            Output("\tDriver provides basic functionality when no signed driver is available.");
                                        }
                                    }
                                    index++;
                                }
                                SetupDiDestroyDriverInfoList(devs, devInfo, 0x02 /* SPDIT_COMPATDRIVER */);
                            }
                            if (!success) {
                                Output("\tNo driver nodes found for this device.");
                            }
                        }
                    }
                }
                finally {
                    if (IntPtr.Zero != deviceInstallParams) { Marshal.FreeCoTaskMem(deviceInstallParams); }
                    if (IntPtr.Zero != driverInfoData) { Marshal.FreeCoTaskMem(driverInfoData); }
                    if (IntPtr.Zero != driverInfoDetail) { Marshal.FreeCoTaskMem(driverInfoDetail); }
                    if (IntPtr.Zero != driverInstallParams) { Marshal.FreeCoTaskMem(driverInstallParams); }
                }
                return true;
            }
            finally { if (IntPtr.Zero != details) { Marshal.FreeCoTaskMem(details); } }
        }

        private static bool DumpDeviceResourcesOfType(IntPtr /* HMACHINE */ MachineHandle,
            IntPtr Config, ResourceType ReqResId)
        {
            IntPtr prevResDes = Config;
            IntPtr resDes = IntPtr.Zero;
            ResourceType resId = ReqResId;
            uint dataSize;
            bool retval = false;

            while (0 == CM_Get_Next_Res_Des_Ex(out resDes, prevResDes, ReqResId, out resId, 0, MachineHandle)) {
                if (prevResDes != Config) {
                    CM_Free_Res_Des_Handle(prevResDes);
                }
                prevResDes = resDes;
                if (0 != CM_Get_Res_Des_Data_Size_Ex(out dataSize, resDes, 0, MachineHandle)) {
                    continue;
                }
                IntPtr resDesData = Marshal.AllocCoTaskMem((int)dataSize);
                try {
                    if (0 != CM_Get_Res_Des_Data_Ex(resDes, resDesData, dataSize, 0, MachineHandle)) {
                        continue;
                    }
                    ulong endAddress;
                    ulong startAddress;
                    switch (resId) {
                        case ResourceType.Memory:
                            endAddress = (ulong)Marshal.ReadInt64(resDesData, 16);
                            startAddress = (ulong)Marshal.ReadInt64(resDesData, 8);
                            if (0 < (endAddress - startAddress)) {
                                Output("\t\tMEM : 0x{0:X8}-0x{1:X8}", startAddress, endAddress);
                                retval = true;
                            }
                            break;
                        case ResourceType.IOAddress:
                            endAddress = (ulong)Marshal.ReadInt64(resDesData, 16);
                            startAddress = (ulong)Marshal.ReadInt64(resDesData, 8);
                            if (0 < (endAddress - startAddress)) {
                                Output("\t\tIO  : 0x{0:X8}-0x{1:X8}", startAddress, endAddress);
                                retval = true;
                            }
                            break;
                        case ResourceType.DMAChannel:
                            Output("\t\tDMA : {0}", Marshal.ReadInt32(resDesData, 12));
                            retval = true;
                            break;
                        case ResourceType.IRQ:
                            Output("\t\tIRQ : 0x{0:X8}", (uint)Marshal.ReadInt32(resDesData, 12));
                            retval = true;
                            break;
                    }
                }
                finally { Marshal.FreeCoTaskMem(resDesData); }
            }
            if (prevResDes != Config) {
                CM_Free_Res_Des_Handle(prevResDes);
            }
            return retval;
        }

        private static bool DumpDeviceWithInfo(IntPtr devs, IntPtr /* PSP_DEVINFO_DATA */ DevInfo,
            string Info)
        {
            bool result = true;
            //TCHAR devID[MAX_DEVICE_ID_LEN];
            //SP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail;

            //int detailsLength = 560;
            //IntPtr details = Marshal.AllocCoTaskMem(detailsLength);
            //Marshal.WriteInt32(details, detailsLength);
            //if (SetupDiGetDeviceInfoListDetail(devs, details)) { result = false; }
            //else if (CM_Get_Device_ID_Ex(DevInfo->DevInst, devID, MAX_DEVICE_ID_LEN, 0, details.RemoteMachineHandle) != CR_SUCCESS))
            //{
            //    result = false;
            //}
            //if (!result) { StringCchCopy(devID, ARRAYSIZE(devID), "?"); }
            //if (null != Info) { Output("\t{0}s: {1}\n", devID, Info); }
            //else { Output("\t{0}\n", devID); }
            return result;
        }

        private static string GetDeviceStringProperty(IntPtr /* HDEVINFO */ devs,
            IntPtr /* PSP_DEVINFO_DATA */ devInfo, DeviceProperty Prop)
        {
            int requiredSize;
            RegistryDataType dataType;

            int size = 1024; // initial guess
            IntPtr buffer = Marshal.AllocCoTaskMem(size);
            try {
                while (!SetupDiGetDeviceRegistryProperty(devs, devInfo, Prop, out dataType,
                    buffer, size, out requiredSize))
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    switch (errorCode) {
                        case 0:
                            break;
                        case 13:
                            return null;
                        case 122:
                            Marshal.FreeCoTaskMem(buffer);
                            buffer = IntPtr.Zero;
                            buffer = Marshal.AllocCoTaskMem(requiredSize);
                            size = requiredSize;
                            continue;
                        default:
                            throw new ApplicationException(string.Format(
                                "Property retrieval failed with error code {0}.", errorCode));
                    }
                    if (RegistryDataType.String != dataType) {
                        return null;
                    }
                }
                byte[] localArray = new byte[requiredSize];
                Marshal.Copy(buffer, localArray, 0, localArray.Length);
                return Encoding.Unicode.GetString(localArray, 0, requiredSize);
            }
            finally { Marshal.FreeCoTaskMem(buffer); }
        }

        private static List<string> GetDeviceMultiString(IntPtr devs, IntPtr /* PSP_DEVINFO_DATA */ devInfo,
            DeviceProperty property)
        {
            RegistryDataType propertyDataType;
            int size = 8192;
            int requiredSize;
            IntPtr buffer = IntPtr.Zero;

            try {
                buffer = Marshal.AllocCoTaskMem((size / sizeof(char)) + 2);
                while (!SetupDiGetDeviceRegistryProperty(devs, devInfo, property,
                    out propertyDataType, buffer, size, out requiredSize))
                {
                    if (122 != Marshal.GetLastWin32Error()) { return null; }
                    if (RegistryDataType.MultipleStrings != propertyDataType) { return null; }
                    size = requiredSize;
                    Marshal.FreeCoTaskMem(buffer);
                    buffer = IntPtr.Zero;
                    buffer = Marshal.AllocCoTaskMem((size / sizeof(char)) + 2);
                }
                byte[] localBuffer = new byte[requiredSize];
                Marshal.Copy(buffer, localBuffer, 0, localBuffer.Length);
                return new List<string>(Encoding.Unicode.GetString(localBuffer).Split(new char[] { '\0' },
                    StringSplitOptions.RemoveEmptyEntries));
            }
            finally { if (IntPtr.Zero != buffer) { Marshal.FreeCoTaskMem(buffer); } }
        }

        private static string GetNativeString(int charactersCount, IntPtr nativeData,
            int nativeOffset)
        {
            byte[] localBuffer = new byte[sizeof(char) * charactersCount];
            Marshal.Copy(nativeData + nativeOffset, localBuffer, 0, localBuffer.Length);
            string candidate = Encoding.Unicode.GetString(localBuffer);
            int splitAt = candidate.IndexOf('\0');
            return (-1 == splitAt) ? candidate : candidate.Substring(0, splitAt);
        }

        private static List<string> GetRegistryMultiString(IntPtr hKey, string name)
        {
            return GetRegistryMultiString(RegistryKey.FromHandle(new SafeRegistryHandle(hKey, false)), name);
        }

        private static List<string> GetRegistryMultiString(RegistryKey hKey, string name)
        {
            object rawValue = hKey.GetValue(name, null);
            if (null == rawValue) { return null; }
            List<string> result = new List<string>();
            if (rawValue is string) {
                result.AddRange(((string)rawValue).Split('\0'));
                return result;
            }
            if (rawValue is string[]) {
                result.AddRange((string[])rawValue);
                return result;
            }
            throw new NotSupportedException();
        }

        public static int Main(string[] args)
        {
            // AllClasses flag is mandatory, otherwise we get a 6 error code
            // (invalid operation exception).
            IntPtr devs = SetupDiGetClassDevsEx(IntPtr.Zero, null, IntPtr.Zero,
                DeviceRetrievalFlags.AllClasses | DeviceRetrievalFlags.Present,
                IntPtr.Zero, null, IntPtr.Zero);
            int error;
            if (InvalidHandleValue == devs) {
                error = Marshal.GetLastWin32Error();
                return 1;
            }
            try {
                int detailsLength = 560;
                IntPtr details = Marshal.AllocCoTaskMem(detailsLength);
                Marshal.WriteInt32(details, detailsLength);
                if (!SetupDiGetDeviceInfoListDetail(devs, details)) {
                    error = Marshal.GetLastWin32Error();
                    return 2;
                }
                int devInfoLength = 32;
                IntPtr devInfo = Marshal.AllocCoTaskMem(devInfoLength);
                Marshal.WriteInt32(devInfo, devInfoLength);
                for (uint devIndex = 0; SetupDiEnumDeviceInfo(devs, devIndex, devInfo); devIndex++) {
                    DumpDevice(devs, devIndex, devInfo);
                }
                error = Marshal.GetLastWin32Error();
                if (259 != error) {
                    return 4;
                }
                return 0;
            }
            catch (Exception e) {
                Output("Error : {0}.\r\n{1}", e.Message, e.StackTrace);
                return 99;
            }
            finally {
                if (IntPtr.Zero != devs) {
                    SetupDiDestroyDeviceInfoList(devs);
                }
            }
        }

        private static void Output(string format, params object [] args)
        {
            Console.WriteLine(format, args);
        }

        private static readonly IntPtr InvalidHandleValue = new IntPtr((long)-1);
        private static uint KeyRead = (0x00020000 | 0x0001 | 0x0008 | 0x0010) & (~0x00100000);
        [DllImport("Cfgmgr32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int CM_Free_Log_Conf_Handle(
            [In] IntPtr lcLogConf);

        [DllImport("Cfgmgr32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int CM_Free_Res_Des_Handle(
            [In] IntPtr /* RES_DES or DWORD_PTR */rdResDes);

        [DllImport("Cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_DevNode_Status_Ex(
            [Out] out DeviceStatus pulStatus,
            [Out] out Problem pulProblemNumber,
            [In] int /* DEVINST */ dnDevInst,
            [In] uint ulFlags,
            [In] IntPtr /* HMACHINE */ hMachine);

        [DllImport("Cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_First_Log_Conf_Ex(
            [Out] out IntPtr plcLogConf,
            [In] int /* DEVINST */ dnDevInst,
            [In] LogicalConfigurationRetrievalFlags ulFlags,
            [In] IntPtr /* HMACHINE */ hMachine);

        [DllImport("Cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Next_Res_Des_Ex(
            [Out] out IntPtr /* PRES_DES */ prdResDes,
            [In] IntPtr /* RES_DES */ rdResDes,
            [In] ResourceType ForResource,
            [Out] out ResourceType /* PRESOURCEID */ pResourceID,
            [In] LogicalConfigurationRetrievalFlags ulFlags,
            [In] IntPtr /* HMACHINE */ hMachine);

        [DllImport("Cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Res_Des_Data_Ex(
            [In] IntPtr /* RES_DES */ rdResDes,
            [In] IntPtr Buffer,
            [In] uint BufferLen,
            [In] uint ulFlags,
            [In] IntPtr /* HMACHINE */ hMachine);

        [DllImport("Cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Res_Des_Data_Size_Ex(
            [Out] out uint pulSize,
            [In] IntPtr /* RES_DES */ rdResDes,
            [In] uint ulFlags,
            [In] IntPtr /* HMACHINE */ hMachine);

        //[DllImport("Cfgmgr32.dll", CharSet = CharSet.Unicode)]
        //private static extern int CM_Get_Device_ID_Ex(
        //    [In] DEVINST dnDevInst,
        //    [In] IntPtr Buffer,
        //    [In] uint BufferLen,
        //    [In] uint ulFlags,
        //    [In] IntPtr /* HMACHINE */ hMachine);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
        private static extern bool SetupDiBuildDriverInfoList(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] IntPtr /* PSP_DEVINFO_DATA */ DeviceInfoData,
            [In] uint DriverType);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
        private static extern bool SetupDiDestroyDeviceInfoList(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet
        );

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
        private static extern bool SetupDiDestroyDriverInfoList(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] IntPtr /* PSP_DEVINFO_DATA */ DeviceInfoData,
            [In] uint DriverType);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] uint MemberIndex,
            [In] IntPtr /* PSP_DEVINFO_DATA */ DeviceInfoData);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiEnumDriverInfo(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] IntPtr /* PSP_DEVINFO_DATA */ DeviceInfoData,
            [In] uint DriverType,
            [In] int MemberIndex,
            [In] IntPtr /* PSP_DRVINFO_DATA_W */ DriverInfoData);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr /* HDEVINFO */ SetupDiGetClassDevsEx(
            [In] IntPtr ClassGuid,
            [In] string Enumerator,
            [In] IntPtr /* HWND */ hwndParent,
            [In] DeviceRetrievalFlags Flags,
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] string MachineName,
            [In] IntPtr Reserved);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiGetDeviceInfoListDetail(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] IntPtr /* PSP_DEVINFO_LIST_DETAIL_DATA */ DeviceInfoSetDetailData);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiGetDeviceInstallParams(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] IntPtr /* PSP_DEVINFO_DATA */ DeviceInfoData,
            [In] IntPtr /* PSP_DEVINSTALL_PARAMS */ DeviceInstallParams);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiGetDeviceRegistryProperty(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] IntPtr /* PSP_DEVINFO_DATA */ DeviceInfoData,
            [In] DeviceProperty Property,
            [Out] out RegistryDataType PropertyRegDataType,
            [In] IntPtr PropertyBuffer,
            [In] int PropertyBufferSize,
            [Out] out int RequiredSize);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiGetDriverInfoDetail(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] IntPtr /* PSP_DEVINFO_DATA */ DeviceInfoData,
            [In] IntPtr /* PSP_DRVINFO_DATA */ DriverInfoData,
            [In] IntPtr /* PSP_DRVINFO_DETAIL_DATA */ DriverInfoDetailData,
            [In] int DriverInfoDetailDataSize,
            [Out] out int RequiredSize);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiGetDriverInstallParams(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] IntPtr /* PSP_DEVINFO_DATA */ DeviceInfoData,
            [In] IntPtr /* PSP_DRVINFO_DATA */ DriverInfoData,
            [In] IntPtr /* PSP_DRVINSTALL_PARAMS */ DriverInstallParams);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SetupDiOpenClassRegKeyEx(
            [In] IntPtr /* GUID */ ClassGuid,
            [In] uint samDesired,
            [In] uint Flags,
            [In] string MachineName,
            [In] IntPtr Reserved);

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool SetupDiSetDeviceInstallParams(
            [In] IntPtr /* HDEVINFO */ DeviceInfoSet,
            [In] IntPtr /* PSP_DEVINFO_DATA */ DeviceInfoData,
            [In] IntPtr /* PSP_DEVINSTALL_PARAMS */ DeviceInstallParams);

        private enum DeviceProperty
        {
            Description = 0x00000000,  // DeviceDesc (R/W)
            HardwareId = 0x00000001,  // HardwareID (R/W)
            CompatibleIds = 0x00000002,  // CompatibleIDs (R/W)
            Service = 0x00000004,  // Service (R/W)
            Class = 0x00000007,  // Class (R--tied to ClassGUID)
            ClassGuid = 0x00000008,  // ClassGUID (R/W)
            Driver = 0x00000009,  // Driver (R/W)
            ConfigurationFlags  = 0x0000000A,  // ConfigFlags (R/W)
            Mfg = 0x0000000B,  // Mfg (R/W)
            FriendlyName = 0x0000000C, // FriendlyName (R/W)
            LocationInformation = 0x0000000D,  // LocationInformation (R/W)
            PhysicalDeviceObjectName = 0x0000000E,  // PhysicalDeviceObjectName (R)
            Capabilities = 0x0000000F,  // Capabilities (R)
            UINumber = 0x00000010,  // UiNumber (R)
            UpperFilters = 0x00000011,  // UpperFilters (R/W)
            LowerFilters = 0x00000012,  // LowerFilters (R/W)
            BusTypeGuid = 0x00000013,  // BusTypeGUID (R)
            LegacyBusType = 0x00000014,  // LegacyBusType (R)
            BusNumber = 0x00000015,  // BusNumber (R)
            EnumeratorName = 0x00000016,  // Enumerator Name (R)
            Security = 0x00000017,  // Security (R/W, binary form)
            SecuritySds = 0x00000018,  // Security (W, SDS form)
            DeviceType = 0x00000019,  // Device Type (R/W)
            Exclusive = 0x0000001A,  // Device is exclusive-access (R/W)
            Characteristics = 0x0000001B,  // Device Characteristics (R/W)
            Address = 0x0000001C,  // Device Address (R)
            UINumberDescriptionFormat = 0X0000001D,  // UiNumberDescFormat (R/W)
            PowerData = 0x0000001E,  // Device Power Data (R)
            RemovalPolicy = 0x0000001F,  // Removal Policy (R)
            RemovalPolicyHardwaeDefault = 0x00000020, // Hardware Removal Policy (R)
            RemovalPolicyOverride = 0x00000021,  // Removal Policy Override (RW)
            InstallState = 0x00000022,  // Device Install State (R)
            LocationPaths = 0x00000023,  // Device Location Paths (R)
            ContainerId = 0x00000024,  // Base ContainerID (R)
        }

        [Flags()]
        private enum DeviceRetrievalFlags : uint
        {
            None = 0,
            Default = 0x00000001, // only valid with DIGCF_DEVICEINTERFACE
            Present = 0x00000002,
            AllClasses = 0x00000004,
            InCurrentHardwareProfile = 0x00000008,
            SupportDeviceInterface = 0x00000010,
        }

        [Flags()]
        private enum DeviceStatus
        {
            RootEnumerated = 0x00000001, // Was enumerated by ROOT
            DriverLoaded = 0x00000002, // Has Register_Device_Driver
            EnumeratorLoadable = 0x00000004, // Has Register_Enumerator
            Started = 0x00000008, // Is currently configured
            Manual = 0x00000010, // Manually installed
            NeedEnumeration = 0x00000020, // May need reenumeration
            NotFirstTime = 0x00000040, // Has received a config
            HardwareEnum = 0x00000080, // Enum generates hardware ID
            Liar = 0x00000100, // Lied about can reconfig once
            HasMark = 0x00000200, // Not CM_Create_DevInst lately
            HasProblem = 0x00000400, // Need device installer
            Filtered = 0x00000800, // Is filtered
            Moved = 0x00001000, // Has been moved
            Disableable = 0x00002000, // Can be disabled
            Removable = 0x00004000, // Can be removed
            PrivateProblem = 0x00008000, // Has a private problem
            MultiFunctionParent = 0x00010000, // Multi function parent
            MultiFunctionChild = 0x00020000, // Multi function child
            WillBeRemoved = 0x00040000 // DevInst is being removed
        }

        private enum LogicalConfigurationRetrievalFlags
        {
            Basic = 0,
            Filtered,
            Allocated,
            Boot,
            Forced,
            Override,
        }

        private enum Problem
        {
            CM_PROB_NOT_CONFIGURED = 0x00000001, // no config for device
            CM_PROB_DEVLOADER_FAILED = 0x00000002, // service load failed
            CM_PROB_OUT_OF_MEMORY = 0x00000003, // out of memory
            CM_PROB_ENTRY_IS_WRONG_TYPE = 0x00000004, //
            CM_PROB_LACKED_ARBITRATOR = 0x00000005, //
            CM_PROB_BOOT_CONFIG_CONFLICT = 0x00000006, // boot config conflict
            CM_PROB_FAILED_FILTER = 0x00000007, //
            CM_PROB_DEVLOADER_NOT_FOUND = 0x00000008, // Devloader not found
            CM_PROB_INVALID_DATA = 0x00000009, // Invalid ID
            CM_PROB_FAILED_START = 0x0000000A, //
            CM_PROB_LIAR = 0x0000000B, //
            CM_PROB_NORMAL_CONFLICT = 0x0000000C, // config conflict
            CM_PROB_NOT_VERIFIED = 0x0000000D, //
            CM_PROB_NEED_RESTART = 0x0000000E, // requires restart
            CM_PROB_REENUMERATION = 0x0000000F, //
            CM_PROB_PARTIAL_LOG_CONF = 0x00000010, //
            CM_PROB_UNKNOWN_RESOURCE = 0x00000011, // unknown res type
            CM_PROB_REINSTALL = 0x00000012, //
            CM_PROB_REGISTRY = 0x00000013, //
            CM_PROB_VXDLDR = 0x00000014, // WINDOWS 95 ONLY
            CM_PROB_WILL_BE_REMOVED = 0x00000015, // devinst will remove
            CM_PROB_DISABLED = 0x00000016, // devinst is disabled
            CM_PROB_DEVLOADER_NOT_READY = 0x00000017, // Devloader not ready
            CM_PROB_DEVICE_NOT_THERE = 0x00000018, // device doesn't exist
            CM_PROB_MOVED = 0x00000019, //
            CM_PROB_TOO_EARLY = 0x0000001A, //
            CM_PROB_NO_VALID_LOG_CONF = 0x0000001B, // no valid log config
            CM_PROB_FAILED_INSTALL = 0x0000001C, // install failed
            CM_PROB_HARDWARE_DISABLED = 0x0000001D, // device disabled
            CM_PROB_CANT_SHARE_IRQ = 0x0000001E, // can't share IRQ
            CM_PROB_FAILED_ADD = 0x0000001F, // driver failed add
            CM_PROB_DISABLED_SERVICE = 0x00000020, // service's Start = 4
            CM_PROB_TRANSLATION_FAILED = 0x00000021, // resource translation failed
            CM_PROB_NO_SOFTCONFIG = 0x00000022, // no soft config
            CM_PROB_BIOS_TABLE = 0x00000023, // device missing in BIOS table
            CM_PROB_IRQ_TRANSLATION_FAILED = 0x00000024, // IRQ translator failed
            CM_PROB_FAILED_DRIVER_ENTRY = 0x00000025, // DriverEntry() failed.
            CM_PROB_DRIVER_FAILED_PRIOR_UNLOAD = 0x00000026, // Driver should have unloaded.
            CM_PROB_DRIVER_FAILED_LOAD = 0x00000027, // Driver load unsuccessful.
            CM_PROB_DRIVER_SERVICE_KEY_INVALID = 0x00000028, // Error accessing driver's service key
            CM_PROB_LEGACY_SERVICE_NO_DEVICES = 0x00000029, // Loaded legacy service created no devices
            CM_PROB_DUPLICATE_DEVICE = 0x0000002A, // Two devices were discovered with the same name
            CM_PROB_FAILED_POST_START = 0x0000002B, // The drivers set the device state to failed
            CM_PROB_HALTED = 0x0000002C, // This device was failed post start via usermode
            CM_PROB_PHANTOM = 0x0000002D, // The devinst currently exists only in the registry
            CM_PROB_SYSTEM_SHUTDOWN = 0x0000002E, // The system is shutting down
            CM_PROB_HELD_FOR_EJECT = 0x0000002F, // The device is offline awaiting removal
            CM_PROB_DRIVER_BLOCKED = 0x00000030, // One or more drivers is blocked from loading
            CM_PROB_REGISTRY_TOO_LARGE = 0x00000031, // System hive has grown too large
            CM_PROB_SETPROPERTIES_FAILED = 0x00000032, // Failed to apply one or more registry properties  
            CM_PROB_WAITING_ON_DEPENDENCY = 0x00000033, // Device is stalled waiting on a dependency to start
            CM_PROB_UNSIGNED_DRIVER = 0x00000034, // Failed load driver due to unsigned image.   

            NUM_CM_PROB_V1 = 0x00000025,
            NUM_CM_PROB_V2 = 0x00000032,
            NUM_CM_PROB_V3 = 0x00000033,
            NUM_CM_PROB_V4 = 0x00000034,
            NUM_CM_PROB_V5 = 0x00000035,
        }

        private enum RegistryDataType
        {
            None = 0, // No value type
            String = 1, // Unicode nul terminated string
            ExpandableString = 2, // Unicode nul terminated string (with environment variable references)
            Binary = 3, // Free form binary
            Int32 = 4, // 32-bit number
            Int32LittleEndian = 4, // 32-bit number (same as REG_DWORD)
            Int32BigEndian = 5, // 32-bit number
            SymbolicLink = 6, // Symbolic Link (unicode)
            MultipleStrings = 7, // Multiple Unicode strings
            ResourceList = 8, // Resource list in the resource map
            FullResourceDescription = 9, // Resource list in the hardware description
            ResourceRequirementsList = 10,
            Int64 = 11, // 64-bit number
            Int64LittleEndian = 11, // 64-bit number (same as REG_QWORD)
        }

        private enum ResourceType
        {
            All = 0, // Return all resource types
            None = 0, // Arbitration always succeeded
            Memory = 1, // Physical address resource
            IOAddress = 2, // Physical I/O address resource
            DMAChannel = 3, // DMA channels resource
            IRQ = 4, // IRQ resource
            DoNotUse = 5, // Used as spacer to sync subsequent ResTypes w/NT
            BusNumber = 6, // bus number resource
            LargeMemory = 7 // Memory resources >= 4GB
        }

        //private struct SP_DEVINFO_LIST_DETAIL_DATA
        //{
        //    internal uint cbSize;
        //    GUID ClassGuid;
        //    IntPtr /* HANDLE */ RemoteMachineHandle;
        //    TCHAR RemoteMachineName[SP_MAX_MACHINENAME_LENGTH];
        //};
    }
}
