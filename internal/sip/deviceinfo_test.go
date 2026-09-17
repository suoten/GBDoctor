package sip

import (
	"testing"
)

func TestParseDeviceInfoResponse(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>DeviceInfo</CmdType>
<SN>456</SN>
<DeviceID>34020000001320000001</DeviceID>
<Result>OK</Result>
<Manufacturer>Hikvision</Manufacturer>
<Model>DS-2CD2T46</Model>
<FirmwareVersion>V5.7.3</FirmwareVersion>
<DeviceName>前端摄像头01</DeviceName>
</Response>`

	fact := ParseDeviceInfoResponse(body)
	if fact.SN != "456" {
		t.Errorf("SN = %q, want 456", fact.SN)
	}
	if fact.DeviceID != "34020000001320000001" {
		t.Errorf("DeviceID = %q", fact.DeviceID)
	}
	if fact.Manufacturer != "Hikvision" {
		t.Errorf("Manufacturer = %q, want Hikvision", fact.Manufacturer)
	}
	if fact.Model != "DS-2CD2T46" {
		t.Errorf("Model = %q", fact.Model)
	}
	if fact.Firmware != "V5.7.3" {
		t.Errorf("Firmware = %q, want V5.7.3", fact.Firmware)
	}
	if fact.DeviceName != "前端摄像头01" {
		t.Errorf("DeviceName = %q", fact.DeviceName)
	}
	if fact.Result != "OK" {
		t.Errorf("Result = %q, want OK", fact.Result)
	}
}

func TestParseDeviceInfoEmpty(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>DeviceInfo</CmdType>
<SN>789</SN>
<DeviceID>34020000001320000001</DeviceID>
<Result>OK</Result>
</Response>`

	fact := ParseDeviceInfoResponse(body)
	if fact.Manufacturer != "" {
		t.Errorf("Manufacturer should be empty, got %q", fact.Manufacturer)
	}
	if fact.Model != "" {
		t.Errorf("Model should be empty, got %q", fact.Model)
	}
}

func TestParseAlarmNotification(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<Notify>
<CmdType>Alarm</CmdType>
<SN>100</SN>
<DeviceID>34020000001320000001</DeviceID>
<AlarmMethod>5</AlarmMethod>
<AlarmType>1</AlarmType>
<AlarmTime>2026-09-16 10:30:00</AlarmTime>
<Description>移动侦测报警</Description>
<Longitude>116.3974</Longitude>
<Latitude>39.9093</Latitude>
</Notify>`

	fact := ParseAlarmNotification(body)
	if fact.SN != "100" {
		t.Errorf("SN = %q, want 100", fact.SN)
	}
	if fact.DeviceID != "34020000001320000001" {
		t.Errorf("DeviceID = %q", fact.DeviceID)
	}
	if fact.AlarmMethod != "5" {
		t.Errorf("AlarmMethod = %q, want 5", fact.AlarmMethod)
	}
	if fact.AlarmType != "1" {
		t.Errorf("AlarmType = %q, want 1", fact.AlarmType)
	}
	if fact.AlarmTime != "2026-09-16 10:30:00" {
		t.Errorf("AlarmTime = %q", fact.AlarmTime)
	}
	if fact.Description != "移动侦测报警" {
		t.Errorf("Description = %q", fact.Description)
	}
	if fact.Longitude != "116.3974" {
		t.Errorf("Longitude = %q", fact.Longitude)
	}
	if fact.Latitude != "39.9093" {
		t.Errorf("Latitude = %q", fact.Latitude)
	}
}

func TestParseRecordInfoResponse(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>RecordInfo</CmdType>
<SN>200</SN>
<DeviceID>34020000001320000001</DeviceID>
<Name>摄像头01</Name>
<SumNum>2</SumNum>
<Item>
<DeviceID>34020000001320000001</DeviceID>
<Name>录像段1</Name>
<FilePath>/record/2026-09-16/001.mp4</FilePath>
<Address>192.168.1.100</Address>
<StartTime>2026-09-16 08:00:00</StartTime>
<EndTime>2026-09-16 09:00:00</EndTime>
<RecType>1</RecType>
</Item>
<Item>
<DeviceID>34020000001320000001</DeviceID>
<Name>录像段2</Name>
<FilePath>/record/2026-09-16/002.mp4</FilePath>
<Address>192.168.1.100</Address>
<StartTime>2026-09-16 09:00:00</StartTime>
<EndTime>2026-09-16 10:00:00</EndTime>
<RecType>1</RecType>
</Item>
</Response>`

	fact := ParseRecordInfoResponse(body)
	if fact.SN != "200" {
		t.Errorf("SN = %q, want 200", fact.SN)
	}
	if fact.DeviceID != "34020000001320000001" {
		t.Errorf("DeviceID = %q", fact.DeviceID)
	}
	if fact.SumNum != "2" {
		t.Errorf("SumNum = %q, want 2", fact.SumNum)
	}
	if len(fact.Items) != 2 {
		t.Fatalf("Items count = %d, want 2", len(fact.Items))
	}
	if fact.Items[0].FilePath != "/record/2026-09-16/001.mp4" {
		t.Errorf("Item[0] FilePath = %q", fact.Items[0].FilePath)
	}
	if fact.Items[0].StartTime != "2026-09-16 08:00:00" {
		t.Errorf("Item[0] StartTime = %q", fact.Items[0].StartTime)
	}
	if fact.Items[1].EndTime != "2026-09-16 10:00:00" {
		t.Errorf("Item[1] EndTime = %q", fact.Items[1].EndTime)
	}
}

func TestParseRecordInfoEmpty(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>RecordInfo</CmdType>
<SN>201</SN>
<DeviceID>34020000001320000001</DeviceID>
<SumNum>0</SumNum>
</Response>`

	fact := ParseRecordInfoResponse(body)
	if len(fact.Items) != 0 {
		t.Errorf("Items count = %d, want 0", len(fact.Items))
	}
	if fact.SumNum != "0" {
		t.Errorf("SumNum = %q, want 0", fact.SumNum)
	}
}

func TestCheckClockSync(t *testing.T) {
	// 测试正常时间格式
	fact := CheckClockSync("2026-09-16T10:30:00", "34020000001320000001")
	if fact.DeviceID != "34020000001320000001" {
		t.Errorf("DeviceID = %q", fact.DeviceID)
	}
	if fact.DeviceTime.IsZero() {
		t.Error("DeviceTime 不应为零值")
	}
	if fact.PlatformTime.IsZero() {
		t.Error("PlatformTime 不应为零值")
	}

	// 测试无法解析的时间
	fact2 := CheckClockSync("invalid-time", "34020000001320000001")
	if !fact2.DeviceTime.IsZero() {
		t.Error("无效时间应保持零值")
	}
	if fact2.Offset != 0 {
		t.Error("无法解析时偏移应为 0")
	}
}

func TestClockOffsetConclusions(t *testing.T) {
	// 严重偏差
	conclusions := ClockOffsetConclusions(10 * 60e9) // 10 minutes
	if len(conclusions) == 0 {
		t.Error("应返回结论")
	}

	// 正常偏差
	conclusions2 := ClockOffsetConclusions(5 * 1e9) // 5 seconds
	if len(conclusions2) == 0 {
		t.Error("应返回结论")
	}
}
