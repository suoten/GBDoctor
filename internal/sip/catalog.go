package sip

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CatalogItem 为目录中的一个通道/设备条目。
type CatalogItem struct {
	DeviceID     string
	Name         string
	Manufacturer string
	Model        string
	Owner        string
	CivilCode    string
	Address      string
	Parental     string // 0/1
	ParentID     string
	SafetyWay    string
	RegisterWay  string
	Secrecy      string
	IPAddress    string
	Port         string
	Status       string // ON/OFF
	Longitude    string
	Latitude     string
	SubCount     string
}

// CatalogFact 为目录查询结果事实。
type CatalogFact struct {
	DeviceID string
	Source   string
	SN       string
	Items    []CatalogItem
	ErrCode  string
	ErrMSg   string
	TS       time.Time
	RawBody  string
}

// QueryCatalog 发送目录查询 MESSAGE 给已注册设备。
func (r *DeviceSideRole) QueryCatalog(deviceID string) error {
	session, ok := r.Session(deviceID)
	if !ok {
		return fmt.Errorf("设备 %s 未注册", deviceID)
	}
	sn := int(time.Now().UnixNano() % 100000)
	xmlBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Query>
<CmdType>Catalog</CmdType>
<SN>%d</SN>
<DeviceID>%s</DeviceID>
</Query>`, sn, deviceID)

	return r.sendPlatformMessage(deviceID, session, xmlBody)
}

// ParseCatalogResponse 解析目录应答 XML，提取通道列表。
func ParseCatalogResponse(body string) CatalogFact {
	fact := CatalogFact{
		TS:      time.Now(),
		RawBody: body,
	}
	fact.SN = XMLTagValue(body, "SN")
	fact.DeviceID = XMLTagValue(body, "DeviceID")
	fact.ErrCode = XMLTagValue(body, "ErrCode")
	fact.ErrMSg = XMLTagValue(body, "ErrMSg")

	lower := strings.ToLower(body)
	startTag := "<item>"
	endTag := "</item>"

	idx := 0
	for {
		start := strings.Index(lower[idx:], startTag)
		if start < 0 {
			break
		}
		start += idx
		end := strings.Index(lower[start:], endTag)
		if end < 0 {
			break
		}
		end += start + len(endTag)
		itemXML := body[start:end]

		item := CatalogItem{
			DeviceID:     XMLTagValue(itemXML, "DeviceID"),
			Name:         XMLTagValue(itemXML, "Name"),
			Manufacturer: XMLTagValue(itemXML, "Manufacturer"),
			Model:        XMLTagValue(itemXML, "Model"),
			Owner:        XMLTagValue(itemXML, "Owner"),
			CivilCode:    XMLTagValue(itemXML, "CivilCode"),
			Address:      XMLTagValue(itemXML, "Address"),
			Parental:     XMLTagValue(itemXML, "Parental"),
			ParentID:     XMLTagValue(itemXML, "ParentID"),
			SafetyWay:    XMLTagValue(itemXML, "SafetyWay"),
			RegisterWay:  XMLTagValue(itemXML, "RegisterWay"),
			Secrecy:      XMLTagValue(itemXML, "Secrecy"),
			IPAddress:    XMLTagValue(itemXML, "IPAddress"),
			Port:         XMLTagValue(itemXML, "Port"),
			Status:       XMLTagValue(itemXML, "Status"),
			Longitude:    XMLTagValue(itemXML, "Longitude"),
			Latitude:     XMLTagValue(itemXML, "Latitude"),
			SubCount:     XMLTagValue(itemXML, "SubCount"),
		}
		fact.Items = append(fact.Items, item)
		idx = end
	}

	return fact
}

// CatalogItemValidations 对单个目录条目执行规范性校验，返回偏差列表。
func CatalogItemValidations(item CatalogItem) []Deviation {
	var devs []Deviation

	if item.DeviceID == "" {
		devs = append(devs, Deviation{Kind: "catalog_deviceid_empty", Detail: "通道 DeviceID 为空"})
	} else if len(item.DeviceID) != 20 {
		devs = append(devs, Deviation{Kind: "catalog_deviceid_length", Detail: fmt.Sprintf("DeviceID 长度=%d，国标要求 20 位: %s", len(item.DeviceID), item.DeviceID)})
	} else {
		for i := 0; i < len(item.DeviceID); i++ {
			if item.DeviceID[i] < '0' || item.DeviceID[i] > '9' {
				devs = append(devs, Deviation{Kind: "catalog_deviceid_charset", Detail: fmt.Sprintf("DeviceID 含非数字字符: %s", item.DeviceID)})
				break
			}
		}
	}

	if item.Name == "" {
		devs = append(devs, Deviation{Kind: "catalog_name_empty", Detail: "通道名称为空"})
	}

	if item.Parental != "" && item.Parental != "0" && item.Parental != "1" {
		devs = append(devs, Deviation{Kind: "catalog_parental", Detail: fmt.Sprintf("Parental 值=%s，应为 0 或 1", item.Parental)})
	}

	if item.Status != "" && item.Status != "ON" && item.Status != "OFF" {
		devs = append(devs, Deviation{Kind: "catalog_status", Detail: fmt.Sprintf("Status 值=%s，应为 ON 或 OFF", item.Status)})
	}

	return devs
}

// SumNum 从目录应答中提取 SumNum（总通道数）。
func SumNum(body string) int {
	v := XMLTagValue(body, "SumNum")
	if v == "" {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

// nextPlatformCSeq 生成平台侧下一个 CSeq 序号（实例级计数器，避免多实例竞争包级变量）。
func (r *DeviceSideRole) nextPlatformCSeq() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.platformCSeq++
	return r.platformCSeq + 1000
}
