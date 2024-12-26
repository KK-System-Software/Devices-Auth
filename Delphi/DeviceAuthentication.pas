unit DeviceAuthentication;

//==========================================================================================================================
// *** Summary ***
// This class supports authentication by obtaining the serial numbers of devices and systems such as Windows via WMI.
// This allows applications to be restricted from launching or restricting functionality outside of certain environments.
// *** Notes ***
// 1. It may or may not work properly in environments where WMI is disabled.
// 2. If parts are replaced for repair or other reasons, authentication may fail.
//==========================================================================================================================

interface

uses
  System.Classes, System.SysUtils, System.Variants, System.Hash,
  Winapi.Windows, Winapi.ActiveX, Winapi.Wbem;

type
  TWQL = class
  public
    WbemServer: IWbemServices;
    function ConnectSetup():Boolean ;
    function GetRecord(Query: String; var EnumWbemClassObject: IEnumWbemClassObject): Boolean;
    function GetString(Query: String; ValueName: String; var Value: String):Boolean ;
    constructor Create();
  end;

type
  THardwareAuthentication = class(TWQL)
  public
    constructor Create(AOwner: TComponent);
    function AuthComputerSerialNumber(const SerialNumbers: array of String): Boolean;
    function AuthBaseBoardSerialNumber(const SerialNumbers: array of String): Boolean;
    function AuthSystemDisk(const SerialNumbers: array of String):Boolean ;
    function AuthSystemDiskEx(const InstancePaths: array of String):Boolean ;
    function AuthExternalDisk(const SerialNumbers: array of String):Boolean ;
    function AuthExternalDiskEx(const InstancePaths: array of String):Boolean ;
  end;

type
  TSoftwareAuthentication = class(TWQL)
type
  HashFunc= (MD5, SHA1, SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256);
  public
    constructor Create(AOwner: TComponent);
    function AuthWindowsSerialNumber(const SerialNumbers: array of String):Boolean ;
    function AuthUserAccountSID(const Sids: array of String):Boolean ;
    function AuthUserAccount(UserName, DomainName, Password: String):Boolean ;
    function AuthFileHash(const FilePath, Hash: String; Func: HashFunc):Boolean ;
    //function LogonUser(UserName: String; DomainName: String; Password: String; out Token:
  end;

implementation

const
  WQUERY_BASIC = 'SELECT * FROM %s';
  WQUERY_WHERE1 = 'SELECT * FROM %s WHERE %s = ''%s''';
  WQUERY_WHERE2 = 'SELECT * FROM %s WHERE %s <> ''%s''';
  WCLASS_BIOS = 'Win32_BIOS';
  WCLASS_BASEBOARD = 'Win32_BaseBoard';
  WCLASS_DISK = 'Win32_DiskDrive';
  WCLASS_OS = 'Win32_OperatingSystem';
  WPROP_SN = 'SerialNumber';
  WPROP_ID = 'PNPDeviceID';
  WPROP_IT = 'InterfaceType';
  WPROPVALUE_IDE = 'IDE';

resourceString
  MSG_INVALIDPARAMSERROR = 'Invalid parameter.';
  MSG_QUERYERROR = 'An error occurred while executing the query.';
  MSG_WMICONNECTERROR = 'Could not connect to WMI.';
  MSG_FAILEDTOAUTHDEVICE = 'Failed to authenticate device.';
  MSG_AUTHDEVICEREMOVED = 'Authentication device removed.';

{ THardwareAuthentication }


function THardwareAuthentication.AuthComputerSerialNumber(const SerialNumbers: array of String): Boolean;
var
  EnumClassObject: IEnumWbemClassObject;
  ClassObject: IWbemClassObject;
  Count: DWORD;
  Value: OleVariant;
  SerialNumber: String;
  IsMatch: Boolean;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMSERROR);
  end;

  IsMatch := False;
  if Not(GetRecord(PChar(Format(WQUERY_BASIC, [WCLASS_BIOS])), EnumClassObject)) then
  begin
    raise EArgumentException.Create(MSG_QUERYERROR);
  end;

  while EnumClassObject.Next(Integer(WBEM_INFINITE), 1, ClassObject, Count) = S_OK do
  begin
    VariantInit(Value);
    if ClassObject.Get(WPROP_SN, 0, Value, nil, nil) = NO_ERROR then
    begin
      for SerialNumber in SerialNumbers do
      begin
        if SerialNumber = VarToStr(Value) then
        begin
          IsMatch:= True;
        end;
      end;
    end;
  end;

  VariantClear(Value);
  Result := IsMatch;
end;

function THardwareAuthentication.AuthBaseBoardSerialNumber(const SerialNumbers: array of String): Boolean;
var
  EnumClassObject: IEnumWbemClassObject;
  ClassObject: IWbemClassObject;
  Count: DWORD;
  Value: OleVariant;
  SerialNumber: String;
  IsMatch: Boolean;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMSERROR);
  end;

  IsMatch := False;
  if Not(GetRecord(PChar(Format(WQUERY_BASIC, [WCLASS_BASEBOARD])), EnumClassObject)) then
  begin
    raise EArgumentException.Create(MSG_QUERYERROR);
  end;

  while EnumClassObject.Next(Integer(WBEM_INFINITE), 1, ClassObject, Count) = S_OK do
  begin
    VariantInit(Value);
    if ClassObject.Get(WPROP_SN, 0, Value, nil, nil) = NO_ERROR then
    begin
      for SerialNumber in SerialNumbers do
      begin
        if SerialNumber = VarToStr(Value) then
        begin
          IsMatch:= True;
        end;
      end;
    end;
  end;

  VariantClear(Value);
  Result := IsMatch
end;


function THardwareAuthentication.AuthExternalDisk(const SerialNumbers: array of String): Boolean;
var
  EnumClassObject: IEnumWbemClassObject;
  ClassObject: IWbemClassObject;
  Count: DWORD;
  Value: OleVariant;
  SerialNumber: String;
  IsMatch: Boolean;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMSERROR);
  end;

  IsMatch := False;
  if Not(GetRecord(PChar(Format(WQUERY_WHERE2, [WCLASS_DISK, WPROP_IT, WPROPVALUE_IDE])), EnumClassObject)) then
  begin
    raise EArgumentException.Create(MSG_QUERYERROR);
  end;

  while EnumClassObject.Next(Integer(WBEM_INFINITE), 1, ClassObject, Count) = S_OK do
  begin
    VariantInit(Value);
    if ClassObject.Get(WPROP_SN, 0, Value, nil, nil) = NO_ERROR then
    begin
      for SerialNumber in SerialNumbers do
      begin
        if SerialNumber = VarToStr(Value) then
        begin
          IsMatch:= True;
        end;
      end;
    end;
  end;

  VariantClear(Value);
  Result := IsMatch;
end;

function THardwareAuthentication.AuthExternalDiskEx(const InstancePaths: array of String): Boolean;
var
  EnumClassObject: IEnumWbemClassObject;
  ClassObject: IWbemClassObject;
  Count: DWORD;
  Value: OleVariant;
  InstancePath: String;
  IsMatch: Boolean;
begin
  if Length(InstancePaths) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMSERROR);
  end;

  IsMatch := False;
  if Not(GetRecord(PChar(Format(WQUERY_WHERE2, [WCLASS_DISK, WPROP_IT, WPROPVALUE_IDE])), EnumClassObject)) then
  begin
    raise EArgumentException.Create(MSG_QUERYERROR);
  end;

  while EnumClassObject.Next(Integer(WBEM_INFINITE), 1, ClassObject, Count) = S_OK do
  begin
    VariantInit(Value);
    if ClassObject.Get(WPROP_ID, 0, Value, nil, nil) = NO_ERROR then
    begin
      for InstancePath in InstancePaths do
      begin
        if InstancePath = VarToStr(Value) then
        begin
          IsMatch:= True;
        end;
      end;
    end;
  end;

  VariantClear(Value);
  Result := IsMatch;
end;

function THardwareAuthentication.AuthSystemDisk(const SerialNumbers: array of String): Boolean;
var
  EnumClassObject: IEnumWbemClassObject;
  ClassObject: IWbemClassObject;
  Count: DWORD;
  Value: OleVariant;
  SerialNumber: String;
  IsMatch: Boolean;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMSERROR);
  end;

  IsMatch := False;
  if Not(GetRecord(PChar(Format(WQUERY_WHERE1, [WCLASS_DISK, WPROP_IT, WPROPVALUE_IDE])), EnumClassObject)) then
  begin
    raise EArgumentException.Create(MSG_QUERYERROR);
  end;

  while EnumClassObject.Next(Integer(WBEM_INFINITE), 1, ClassObject, Count) = S_OK do
  begin
    VariantInit(Value);
    if ClassObject.Get(WPROP_SN, 0, Value, nil, nil) = NO_ERROR then
    begin
      for SerialNumber in SerialNumbers do
      begin
        if SerialNumber = VarToStr(Value) then
        begin
          IsMatch:= True;
        end;
      end;
    end;
  end;

  VariantClear(Value);
  Result := IsMatch;
end;

function THardwareAuthentication.AuthSystemDiskEx(const InstancePaths: array of String): Boolean;
var
  EnumClassObject: IEnumWbemClassObject;
  ClassObject: IWbemClassObject;
  Count: DWORD;
  Value: OleVariant;
  InstancePath: String;
  IsMatch: Boolean;
begin
  if Length(InstancePaths) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMSERROR);
  end;

  IsMatch := False;
  if Not(GetRecord(PChar(Format(WQUERY_WHERE1, [WCLASS_DISK, WPROP_IT, WPROPVALUE_IDE])), EnumClassObject)) then
  begin
    raise EArgumentException.Create(MSG_QUERYERROR);
  end;

  while EnumClassObject.Next(Integer(WBEM_INFINITE), 1, ClassObject, Count) = S_OK do
  begin
    VariantInit(Value);
    if ClassObject.Get(WPROP_ID, 0, Value, nil, nil) = NO_ERROR then
    begin
      for InstancePath in InstancePaths do
      begin
        if InstancePath = VarToStr(Value) then
        begin
          IsMatch:= True;
        end;
      end;
    end;
  end;

  VariantClear(Value);
  Result := IsMatch;
end;

constructor THardwareAuthentication.Create(AOwner: TComponent);
begin
  inherited Create();
end;

{ TSoftwareAuthentication }

function TSoftwareAuthentication.AuthFileHash(const FilePath, Hash: String; Func: HashFunc): Boolean;
var
  HashValue: String;
  HashType: Integer;
  HashMD5: THashMD5;
  HashSHA1: THashSHA1;
  HashSHA2: THashSHA2;
begin
  HashValue:= String.Empty;
  HashType:= 0;

  case Func of
    MD5:
    begin
      HashMD5:= THashMD5.Create();
      HashValue:= HashMD5.GetHashStringFromFile(FilePath);
    end;

    SHA1:
    begin
      HashSHA1:= THashSHA1.Create();
      HashValue:= HashSHA1.GetHashStringFromFile(FilePath);
    end;

    SHA224..SHA512_256:
    begin
      HashSHA2:= THashSHA2.Create();
      HashType:= Integer(Func) - 2;
      HashValue:= HashSHA2.GetHashStringFromFile(FilePath, THashSHA2.TSHA2Version(HashType));
    end;
  end;

  if HashValue = String.Empty then
  begin
    Result:= False;
    Exit;
  end;

  Result:= (Hash = HashValue);
end;

function TSoftwareAuthentication.AuthUserAccount(UserName, DomainName,
  Password: String): Boolean;
var
  Token: NativeUInt;
begin
  Result := LogonUser(PChar(UserName), PChar(DomainName), PChar(Password), 2, 0, Token);
  CloseHandle(Token);
end;

function TSoftwareAuthentication.AuthUserAccountSID(const Sids: array of String): Boolean;
var
  IsMatch: Boolean;
  SidText: String;
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
    Result:= False;
    Exit;
  end;

  ConvertSidToStringSid(Sid, SidTextConvert);
  for SidText in Sids do
  begin
    if SidText = SidTextConvert then
    begin
      IsMatch:= True;
    end;
  end;

  LocalFree(SidTextConvert);

  Result:= IsMatch;
end;

function TSoftwareAuthentication.AuthWindowsSerialNumber(const SerialNumbers: array of String): Boolean;
var
  EnumClassObject: IEnumWbemClassObject;
  ClassObject: IWbemClassObject;
  Count: DWORD;
  Value: OleVariant;
  SerialNumber: String;
  IsMatch: Boolean;
begin
  if Length(SerialNumbers) = 0 then
  begin
    raise EArgumentException.Create(MSG_INVALIDPARAMSERROR);
  end;

  IsMatch := False;
  if Not(GetRecord(PChar(Format(WQUERY_BASIC, [WCLASS_OS])), EnumClassObject)) then
  begin
    raise EArgumentException.Create(MSG_QUERYERROR);
  end;

  while EnumClassObject.Next(Integer(WBEM_INFINITE), 1, ClassObject, Count) = S_OK do
  begin
    VariantInit(Value);
    if ClassObject.Get(WPROP_SN, 0, Value, nil, nil) = NO_ERROR then
    begin
      for SerialNumber in SerialNumbers do
      begin
        if SerialNumber = VarToStr(Value) then
        begin
          IsMatch:= True;
        end;
      end;
    end;
  end;

  VariantClear(Value);
  Result := IsMatch;
end;

constructor TSoftwareAuthentication.Create(AOwner: TComponent);
begin
  inherited Create();
end;

{ TWQL }

function TWQL.ConnectSetup(): Boolean;
const
  LOCALHOST= 'localhost';
  CIMV2= '\\%s\root\CIMV2';
  RPC_C_AUTHN_WINNT = 10;
  RPC_C_AUTHN_NONE = 0;
  RPC_C_AUTHN_LEVEL_CALL = 3;
  RPC_C_IMP_LEVEL_IMPERSONATE = 3;
var
  Res: HRESULT;
  WbemLocator: IWbemLocator;
begin
  Res := CoCreateInstance(
                      CLSID_WbemLocator,
                      nil,
                      CLSCTX_INPROC_SERVER,
                      IID_IWbemLocator,
                      WbemLocator
                      );

  if Failed(Res) then
  begin
    Result:= False;
    Exit;
  end;

  Res := WbemLocator.ConnectServer(
                            Format(CIMV2, [LOCALHOST]),
                            EmptyStr,
                            EmptyStr,
                            EmptyStr,
                            WBEM_FLAG_CONNECT_USE_MAX_WAIT,
                            '',
                            nil,
                            WbemServer
                            );

  if Failed(Res) then
  begin
    Result:= False;
    Exit;
  end;

  Res := CoSetProxyBlanket(
              WbemServer,
              RPC_C_AUTHN_WINNT,
              RPC_C_AUTHN_NONE,
              nil,
              RPC_C_AUTHN_LEVEL_CALL,
              RPC_C_IMP_LEVEL_IMPERSONATE,
              nil,
              0
              );

  if Failed(Res) then
  begin
    Result:= False;
    Exit;
  end;

  Result:= True;
end;

constructor TWQL.Create();
begin
  if Not(ConnectSetup()) then
  begin
    raise Exception.Create(MSG_WMICONNECTERROR);
  end;
end;

function TWQL.GetRecord(Query: String; var EnumWbemClassObject: IEnumWbemClassObject): Boolean;
const
  WQL= 'WQL';
var
  Res: HRESULT;
begin
  Res := WbemServer.ExecQuery(
                  WQL,
                  PChar(Query),
                  WBEM_FLAG_FORWARD_ONLY or WBEM_FLAG_RETURN_IMMEDIATELY,
                  nil,
                  EnumWbemClassObject
                  );


  if Failed(Res) then
  begin
    Result:= False;
    Exit;
  end;

  Result:= True;
end;

function TWQL.GetString(Query: String; ValueName: String; var Value: String): Boolean;
var
  EnumWbemClassObject: IEnumWbemClassObject;
  ClassObject: IWbemClassObject;
  ValueVariant: OleVariant;
  Count: DWORD;
begin
  Value:= String.Empty;
  Result:= False;
  EnumWbemClassObject:= nil;
  VariantInit(ValueVariant);

  if Not(GetRecord(Query, EnumWbemClassObject)) then
  begin
    Result:= False;
  end;

  while EnumWbemClassObject.Next(Integer(WBEM_INFINITE),
                                         1, ClassObject, Count) = S_OK do
  begin
    if ClassObject.Get(PChar(ValueName), 0, ValueVariant, nil, nil) = NO_ERROR then
    begin
      Value:= VarToStr(ValueVariant);
    end;
  end;

  Result:= True;
end;


end.
