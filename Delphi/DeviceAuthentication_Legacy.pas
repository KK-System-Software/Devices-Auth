unit DeviceAuthentication;

//==========================================================================================================================
// *** Summary ***
// This class supports authentication by obtaining the serial numbers of devices and systems such as Windows via WMI.
// This allows applications to be restricted from launching or restricting functionality outside of certain environments.
// *** Notes ***
// 1. Must have 'GLibWMI' installed.
// 2. It may or may not work properly in environments where WMI is disabled.
// 3. If parts are replaced for repair or other reasons, authentication may fail.
//==========================================================================================================================

interface

uses
  System.Classes, System.SysUtils, CWMISQL, Winapi.Windows;

type
  THardwareAuthentication = class
  private
    WMISystem: TWMISQL;
  public
    constructor Create(AOwner: TComponent);
    function AuthComputerSerialNumber(const SerialNumbers: array of string): boolean;
    function AuthBaseBoardSerialNumber(const SerialNumbers: array of string): boolean;
    function AuthSystemDisk(const SerialNumbers: array of string):boolean ;
    function AuthSystemDiskEx(const InstancePaths: array of string):boolean ;
    function AuthExternalDisk(const SerialNumbers: array of string):boolean ;
    function AuthExternalDiskEx(const InstancePaths: array of string):boolean ;
  end;

type
  TSoftwareAuthentication = class
  private
    WMISystem: TWMISQL;
  public
    constructor Create(AOwner: TComponent);
    function AuthWindowsSerialNumber(const SerialNumbers: array of string):boolean ;
    function AuthUserAccountSID(const Sids: array of string):boolean ;
    function AuthUserAccount(UserName, DomainName, Password: string):boolean ;
    //function LogonUser(UserName: string; DomainName: string; Password: string; out Token:
  end;

implementation

const
    WQUERY_BASIC = 'SELECT * FROM %s';
    WCLASS_BIOS = 'Win32_BIOS';
    WCLASS_BASEBOARD = 'Win32_BaseBoard';
    WCLASS_DISK = 'Win32_DiskDrive';
    WCLASS_OS = 'Win32_OperatingSystem';
    WPROP_SN = 'SerialNumber';
    WPROP_ID = 'PNPDeviceID';
    WPROP_IT = 'InterfaceType';
    WPROPVALUE_IDE = 'IDE';
    MSG_INVALIDPARAMS = 'Invalid parameter.';

{ THardwareAuthentication }


function THardwareAuthentication.AuthComputerSerialNumber(const SerialNumbers: array of string): boolean;
var
  SerialNumber: string;
  Index: Integer;
  IsMatch: boolean;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMS);
  end;

  IsMatch := false;
  WMISystem.SQL := Format(WQUERY_BASIC, [WCLASS_BIOS]);
  WMISystem.Active := true;
  for Index := 1 to WMISystem.ObjectsCount do
  begin
    WMISystem.ObjectIndex := Index;
    for SerialNumber in SerialNumbers do
    begin
      if SerialNumber = WMISystem.Properties.Values[WPROP_SN] then
      begin
        IsMatch := true;
      end;
    end;
  end;

  Result := IsMatch
end;

function THardwareAuthentication.AuthBaseBoardSerialNumber(const SerialNumbers: array of string): boolean;
var
  SerialNumber: string;
  Index: Integer;
  IsMatch: boolean;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMS);
  end;

  IsMatch := false;
  WMISystem.SQL := Format(WQUERY_BASIC, [WCLASS_BASEBOARD]);
  WMISystem.Active := true;
  for Index := 1 to WMISystem.ObjectsCount do
  begin
    WMISystem.ObjectIndex := Index;
    for SerialNumber in SerialNumbers do
    begin
      if SerialNumber = WMISystem.Properties.Values[WPROP_SN] then
      begin
        IsMatch := true;
      end;
    end;
  end;

  Result := IsMatch
end;


function THardwareAuthentication.AuthExternalDisk(const SerialNumbers: array of string): boolean;
var
  SerialNumber: string;
  TypeInterface: string;
  IsMatch: boolean;
  Index: Integer;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMS);
  end;

  IsMatch := false;
  WMISystem.SQL := Format(WQUERY_BASIC, [WCLASS_DISK]);
  WMISystem.Active := true;
  for Index := 1 to WMISystem.ObjectsCount do
  begin
    WMISystem.ObjectIndex := Index;
    for SerialNumber in SerialNumbers do
    begin
      TypeInterface := WMISystem.Properties.Values[WPROP_IT];
      if (TypeInterface <> WPROPVALUE_IDE) And
            (SerialNumber = WMISystem.Properties.Values[WPROP_SN]) then
      begin
        IsMatch := true;
      end;
    end;
  end;

  Result := IsMatch
end;

function THardwareAuthentication.AuthExternalDiskEx(const InstancePaths: array of string): boolean;
var
  InstancePath: string;
  TypeInterface: string;
  IsMatch: boolean;
  Index: Integer;
begin
  if Length(InstancePaths) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMS);
  end;

  IsMatch := false;
  WMISystem.SQL := Format(WQUERY_BASIC, [WCLASS_DISK]);
  WMISystem.Active := true;
  for Index := 1 to WMISystem.ObjectsCount do
  begin
    WMISystem.ObjectIndex := Index;
    for InstancePath in InstancePaths do
    begin
      TypeInterface := WMISystem.Properties.Values[WPROP_IT];
      if (TypeInterface <> WPROPVALUE_IDE) And
            (InstancePath = WMISystem.Properties.Values[WPROP_ID]) then
      begin
        IsMatch := true;
      end;
    end;
  end;

  Result := IsMatch
end;

function THardwareAuthentication.AuthSystemDisk(const SerialNumbers: array of string): boolean;
var
  SerialNumber: string;
  TypeInterface: string;
  IsMatch: boolean;
  Index: Integer;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMS);
  end;

  IsMatch := false;
  WMISystem.SQL := Format(WQUERY_BASIC, [WCLASS_DISK]);
  WMISystem.Active := true;
  for Index := 1 to WMISystem.ObjectsCount do
  begin
    WMISystem.ObjectIndex := Index;
    for SerialNumber in SerialNumbers do
    begin
      TypeInterface := WMISystem.Properties.Values[WPROP_IT];
      if (TypeInterface = WPROPVALUE_IDE) And
            (SerialNumber = WMISystem.Properties.Values[WPROP_SN]) then
      begin
        IsMatch := true;
      end;
    end;
  end;

  Result := IsMatch
end;

function THardwareAuthentication.AuthSystemDiskEx(const InstancePaths: array of string): boolean;
var
  InstancePath: string;
  TypeInterface: string;
  IsMatch: boolean;
  Index: Integer;
begin
  if Length(InstancePaths) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMS);
  end;

  IsMatch := false;
  WMISystem.SQL := Format(WQUERY_BASIC, [WCLASS_DISK]);
  WMISystem.Active := true;
  for Index := 1 to WMISystem.ObjectsCount do
  begin
    WMISystem.ObjectIndex := Index;
    for InstancePath in InstancePaths do
    begin
      TypeInterface := WMISystem.Properties.Values[WPROP_IT];
      if (TypeInterface = WPROPVALUE_IDE) And
            (InstancePath = WMISystem.Properties.Values[WPROP_ID]) then
      begin
        IsMatch := true;
      end;
    end;
  end;

  Result := IsMatch
end;

constructor THardwareAuthentication.Create(AOwner: TComponent);
begin
  WMISystem := TWMISQL.Create(AOwner);
end;

{ TSoftwareAuthentication }

function TSoftwareAuthentication.AuthUserAccount(UserName, DomainName,
  Password: string): boolean;
var
  Token: NativeUInt;
begin
  Result := LogonUser(PChar(UserName), PChar(DomainName), PChar(Password), 2, 0, Token);
end;

function TSoftwareAuthentication.AuthUserAccountSID(const Sids: array of string): boolean;
var
  IsMatch: Boolean;
  SidText: string;
  SidBuf: array[0..MAXBYTE] of Byte;
  User: array[0..MAXBYTE] of Char;
  Domain: array[0..MAXBYTE] of Char;
  SidTextConvert: PChar;
  Sid: PSID;
  SidLen: DWORD;
  DomainLen: DWORD;
  UserLen: DWORD;
  SidNameUse: SID_NAME_USE;
begin
  IsMatch := False;
  FillChar(User, SizeOf(User), #0);
  FillChar(Domain, SizeOf(Domain), #0);
  FillChar(SidTextConvert, SizeOf(SidTextConvert), #0);
  FillChar(SidBuf, SizeOf(SidBuf), 0);
  Sid := PSID(@SidBuf);
  SidLen := SizeOf(SidBuf);
  DomainLen := SizeOf(Domain);

  GetUserName(User, UserLen);
  if Not(LookupAccountName(nil, User, Sid, SidLen, Domain, DomainLen, SidNameUse)) then
  begin
    Exit;
  end;

  ConvertSidToStringSid(Sid, SidTextConvert);
  for SidText in Sids do
  begin
    if SidText = SidTextConvert then
    begin
      IsMatch := True;
    end;
  end;

  LocalFree(Sid);
  LocalFree(@User);
  LocalFree(@Domain);
  LocalFree(@SidBuf);
  LocalFree(SidTextConvert);

  Result := IsMatch;
end;

function TSoftwareAuthentication.AuthWindowsSerialNumber(const SerialNumbers: array of string): boolean;
var
  SerialNumber: string;
  IsMatch: boolean;
  Index: Integer;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMS);
  end;

  IsMatch := false;
  WMISystem.SQL := Format(WQUERY_BASIC, [WCLASS_OS]);
  WMISystem.Active := true;
  for Index := 1 to WMISystem.ObjectsCount do
  begin
    WMISystem.ObjectIndex := Index;
    for SerialNumber in SerialNumbers do
    begin
      if SerialNumber = WMISystem.Properties.Values[WPROP_SN] then
      begin
        IsMatch := true;
      end;
    end;
  end;

  Result := IsMatch
end;

constructor TSoftwareAuthentication.Create(AOwner: TComponent);
begin
  WMISystem := TWMISQL.Create(AOwner);
end;
end.
