unit DeviceIdentification;

//==============================================================================
//�y�T�v�z
// WMI��p����PC�̐����ԍ��A�X�g���[�W(�����h���C�u�AUSB�������A�O�t��HDD���j��
// �{�����[���V���A���ԍ��AWindows�̃V���A���ԍ����擾����N���X�Q
// ����̊��ł������삳���Ȃ��A�v���̊J���ɗL��
//�y�g�p���̒��ӓ_�z
// �E�Ώۃv���b�g�t�H�[����Windows�Ɍ���
// �EGLibWMI�̃C���X�g�[�����ς܂��Ă����2��
// �EWMI�𖳌��ɂ��Ă���ꍇ�͎g�p�ł��Ȃ�
//==============================================================================

interface

uses
  System.Classes, CBIOSInfo, CDiskDriveInfo, COperatingSystemInfo;

  type
    THardwareIdentification = class
    private
      BiosInfo : TBIOSInfo;
      DiskDriveInfo : TDiskDriveInfo;
    public
      constructor Create(AOwner : TComponent);
      function IsPCSerialNumberMatch(SerialNumber : string): boolean;
      function IsDiskSerialNumberMatch(SerialNumber : string): boolean;
      function GetPCSerialNumber(): string;
      function GetDisksSerialNumber(): TArray<string>;
  end;

  type
    TSoftwareIdentification = class
    private
      SystemInfo : TOperatingSystemInfo;
    public
      constructor Create(AOwner : TComponent);
      function GetWindowsSerialNumber(): string;
      function IsWindowsSerialNumberMatch(SerialNumber : string): boolean;
  end;

implementation

{ THardwareIdentification }

constructor THardwareIdentification.Create(AOwner : TComponent);
begin
  BiosInfo := TBIOSInfo.Create(AOwner);
  DiskDriveInfo := TDiskDriveInfo.Create(AOwner);
end;

function THardwareIdentification.GetPCSerialNumber: string;
begin
  BiosInfo.Active := true;
  Result := BiosInfo.BIOSProperties.SerialNumber;
end;

function THardwareIdentification.GetDisksSerialNumber(): TArray<string>;
var
  SerialNumbers : TArray<string>;
  Count : Integer;
  I : Integer;
begin
  DiskDriveInfo.Active := true;
  SetLength(SerialNumbers, DiskDriveInfo.ObjectsCount - 1);
  for I := 1 to DiskDriveInfo.ObjectsCount - 1 do
  begin
    DiskDriveInfo.ObjectIndex := I;
    SerialNumbers[I - 1] := DiskDriveInfo.DiskDriveProperties.SerialNumber;
  end;

  Result := SerialNumbers;
end;

function THardwareIdentification.IsDiskSerialNumberMatch(SerialNumber: string): boolean;
var
  SerialNumbers : Tarray<string>;
  IsMatch : Boolean;
  I : Integer;
begin
  IsMatch := false;
  SerialNumbers := GetDisksSerialNumber();
  for I := 0 to Length(SerialNumbers) - 1 do
  begin
    if SerialNumber = SerialNumbers[I] then
    begin
      IsMatch := true;
    end;
  end;

  Result := IsMatch;
end;

function THardwareIdentification.IsPCSerialNumberMatch(SerialNumber : string): boolean;
begin
  Result := SerialNumber = GetPCSerialNumber();
end;

{ TSoftwareIdentification }

constructor TSoftwareIdentification.Create(AOwner: TComponent);
begin
  SystemInfo := TOperatingSystemInfo.Create(AOwner);
end;

function TSoftwareIdentification.GetWindowsSerialNumber: string;
begin
  SystemInfo.Active := true;
  Result := SystemInfo.OperatingSystemProperties.SerialNumber;
end;

function TSoftwareIdentification.IsWindowsSerialNumberMatch(SerialNumber: string): boolean;
begin
  Result := SerialNumber = GetWindowsSerialNumber;
end;

end.
