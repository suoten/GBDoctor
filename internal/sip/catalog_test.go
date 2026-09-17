package sip

import (
	"testing"
	"time"
)

func TestParseCatalogResponse(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<Response>
<CmdType>Catalog</CmdType>
<SN>123</SN>
<DeviceID>34020000001320000001</DeviceID>
<Result>OK</Result>
<SumNum>2</SumNum>
<Item>
<DeviceID>34020000001310000001</DeviceID>
<Name>摄像头1</Name>
<Manufacturer>Hikvision</Manufacturer>
<Model>DS-2CD</Model>
<Status>ON</Status>
<Parental>0</Parental>
</Item>
<Item>
<DeviceID>34020000001310000002</DeviceID>
<Name>摄像头2</Name>
<Status>OFF</Status>
<Parental>0</Parental>
</Item>
</Response>`

	fact := ParseCatalogResponse(body)
	if fact.SN != "123" {
		t.Errorf("SN = %q, want 123", fact.SN)
	}
	if fact.DeviceID != "34020000001320000001" {
		t.Errorf("DeviceID = %q", fact.DeviceID)
	}
	if len(fact.Items) != 2 {
		t.Fatalf("Items count = %d, want 2", len(fact.Items))
	}
	if fact.Items[0].DeviceID != "34020000001310000001" {
		t.Errorf("Item[0] DeviceID = %q", fact.Items[0].DeviceID)
	}
	if fact.Items[0].Name != "摄像头1" {
		t.Errorf("Item[0] Name = %q", fact.Items[0].Name)
	}
	if fact.Items[0].Status != "ON" {
		t.Errorf("Item[0] Status = %q", fact.Items[0].Status)
	}
}

func TestCatalogItemValidations(t *testing.T) {
	// 合法通道
	good := CatalogItem{
		DeviceID: "34020000001310000001",
		Name:     "摄像头",
		Parental: "0",
		Status:   "ON",
	}
	if devs := CatalogItemValidations(good); len(devs) != 0 {
		t.Errorf("合法通道不应有偏差: %v", devs)
	}

	// DeviceID 含字母
	bad := CatalogItem{
		DeviceID: "3402000000131000000a",
		Name:     "摄像头",
	}
	if devs := CatalogItemValidations(bad); len(devs) == 0 {
		t.Errorf("含字母 DeviceID 应有偏差")
	}

	// DeviceID 长度不对
	short := CatalogItem{
		DeviceID: "123",
		Name:     "test",
	}
	if devs := CatalogItemValidations(short); len(devs) == 0 {
		t.Errorf("短 DeviceID 应有偏差")
	}

	// 名称为空
	noName := CatalogItem{
		DeviceID: "34020000001310000001",
	}
	if devs := CatalogItemValidations(noName); len(devs) == 0 {
		t.Errorf("名称为空应有偏差")
	}
}

func TestQueryCatalog(t *testing.T) {
	role, port := newTestRole(t)

	// 先注册设备
	cam := newCam(port, "12345678")
	defer cam.Close()
	if resp, _, err := cam.Register(); err != nil || resp.StatusCode != 200 {
		t.Fatalf("注册失败: %v %v", resp, err)
	}

	// 发送目录查询
	if err := role.QueryCatalog("34020000001320000001"); err != nil {
		t.Fatalf("QueryCatalog 失败: %v", err)
	}

	// 验证证据条数增加（至少有出站查询报文）
	time.Sleep(200 * time.Millisecond)
	if role.Evidence().Count() < 2 {
		t.Errorf("证据应至少 2 条（注册+查询）: %d", role.Evidence().Count())
	}
}
