package sip

import (
	"fmt"
	"strings"
	"time"
)

// DeviceInfoFact 为设备信息查询结果事实。
type DeviceInfoFact struct {
	DeviceID     string
	Source       string
	SN           string
	Manufacturer string
	Model        string
	Firmware     string
	DeviceName   string
	Result       string
	TS           time.Time
	RawBody      string
}

// ParseDeviceInfoResponse 解析设备信息应答 XML。
func ParseDeviceInfoResponse(body string) DeviceInfoFact {
	fact := DeviceInfoFact{
		TS:      time.Now(),
		RawBody: body,
	}
	fact.SN = XMLTagValue(body, "SN")
	fact.DeviceID = XMLTagValue(body, "DeviceID")
	fact.Manufacturer = XMLTagValue(body, "Manufacturer")
	fact.Model = XMLTagValue(body, "Model")
	fact.Firmware = XMLTagValue(body, "FirmwareVersion")
	fact.DeviceName = XMLTagValue(body, "DeviceName")
	fact.Result = XMLTagValue(body, "Result")
	return fact
}

// AlarmFact 为报警通知事实。
type AlarmFact struct {
	DeviceID    string
	Source      string
	SN          string
	AlarmMethod string
	AlarmType   string
	AlarmTime   string
	Description string
	Longitude   string
	Latitude    string
	TS          time.Time
	RawBody     string
}

// ParseAlarmNotification 解析报警通知 XML。
func ParseAlarmNotification(body string) AlarmFact {
	fact := AlarmFact{
		TS:      time.Now(),
		RawBody: body,
	}
	fact.SN = XMLTagValue(body, "SN")
	fact.DeviceID = XMLTagValue(body, "DeviceID")
	fact.AlarmMethod = XMLTagValue(body, "AlarmMethod")
	fact.AlarmType = XMLTagValue(body, "AlarmType")
	fact.AlarmTime = XMLTagValue(body, "AlarmTime")
	fact.Description = XMLTagValue(body, "Description")
	fact.Longitude = XMLTagValue(body, "Longitude")
	fact.Latitude = XMLTagValue(body, "Latitude")
	return fact
}

// RecordItem 为录像检索结果中的一个条目。
type RecordItem struct {
	DeviceID  string
	Name      string
	FilePath  string
	Address   string
	StartTime string
	EndTime   string
	RecType   string
	Secrecy   string
}

// RecordInfoFact 为录像检索结果事实。
type RecordInfoFact struct {
	DeviceID string
	Source   string
	SN       string
	Name     string
	SumNum   string
	Items    []RecordItem
	ErrCode  string
	ErrMSg   string
	TS       time.Time
	RawBody  string
}

// ParseRecordInfoResponse 解析录像检索应答 XML。
func ParseRecordInfoResponse(body string) RecordInfoFact {
	fact := RecordInfoFact{
		TS:      time.Now(),
		RawBody: body,
	}
	fact.SN = XMLTagValue(body, "SN")
	fact.DeviceID = XMLTagValue(body, "DeviceID")
	fact.Name = XMLTagValue(body, "Name")
	fact.SumNum = XMLTagValue(body, "SumNum")
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
		item := RecordItem{
			DeviceID:  XMLTagValue(itemXML, "DeviceID"),
			Name:      XMLTagValue(itemXML, "Name"),
			FilePath:  XMLTagValue(itemXML, "FilePath"),
			Address:   XMLTagValue(itemXML, "Address"),
			StartTime: XMLTagValue(itemXML, "StartTime"),
			EndTime:   XMLTagValue(itemXML, "EndTime"),
			RecType:   XMLTagValue(itemXML, "RecType"),
			Secrecy:   XMLTagValue(itemXML, "Secrecy"),
		}
		fact.Items = append(fact.Items, item)
		idx = end
	}
	return fact
}

// QueryDeviceInfo 发送设备信息查询 MESSAGE。
func (r *DeviceSideRole) QueryDeviceInfo(deviceID string) error {
	session, ok := r.Session(deviceID)
	if !ok {
		return fmt.Errorf("设备 %s 未注册", deviceID)
	}
	sn := int(time.Now().UnixNano() % 100000)
	xmlBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Query>
<CmdType>DeviceInfo</CmdType>
<SN>%d</SN>
<DeviceID>%s</DeviceID>
</Query>`, sn, deviceID)

	return r.sendPlatformMessage(deviceID, session, xmlBody)
}

// QueryRecordInfo 发送录像检索查询 MESSAGE。
func (r *DeviceSideRole) QueryRecordInfo(deviceID, startTime, endTime string) error {
	session, ok := r.Session(deviceID)
	if !ok {
		return fmt.Errorf("设备 %s 未注册", deviceID)
	}
	sn := int(time.Now().UnixNano() % 100000)
	xmlBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Query>
<CmdType>RecordInfo</CmdType>
<SN>%d</SN>
<DeviceID>%s</DeviceID>
<StartTime>%s</StartTime>
<EndTime>%s</EndTime>
<IndistinctQuery>0</IndistinctQuery>
</Query>`, sn, deviceID, startTime, endTime)

	return r.sendPlatformMessage(deviceID, session, xmlBody)
}

// SubscribeAlarm 订阅报警通知。
func (r *DeviceSideRole) SubscribeAlarm(deviceID string, expires int) error {
	_, err := r.SubscribeAlarmWait(deviceID, expires, 0)
	return err
}

// SubscribeAlarmWait 订阅报警通知并等待设备确认应答。
// timeout <= 0 等同 SubscribeAlarm（fire-and-forget）。
func (r *DeviceSideRole) SubscribeAlarmWait(deviceID string, expires int, timeout time.Duration) (*SipMessage, error) {
	session, ok := r.Session(deviceID)
	if !ok {
		return nil, fmt.Errorf("设备 %s 未注册", deviceID)
	}
	sn := int(time.Now().UnixNano() % 100000)
	xmlBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Subscribe>
<CmdType>Alarm</CmdType>
<SN>%d</SN>
<DeviceID>%s</DeviceID>
<Expires>%d</Expires>
</Subscribe>`, sn, deviceID, expires)

	return r.sendPlatformMessageWait(deviceID, session, xmlBody, timeout)
}

// sendPlatformMessage 平台向设备发送 MESSAGE（内部通用方法，不等待应答）。
func (r *DeviceSideRole) sendPlatformMessage(deviceID string, session RegisterSession, xmlBody string) error {
	_, err := r.sendPlatformMessageWait(deviceID, session, xmlBody, 0)
	return err
}

// sendPlatformMessageWait 平台向设备发送 MESSAGE 并等待最终应答。
// timeout <= 0 表示不等待（fire-and-forget）。
// 设备对 MESSAGE 的 200 OK 是命令/订阅是否被接受的唯一权威证据，
// 只看“报文已写入 UDP socket”会产出假通过结果。
func (r *DeviceSideRole) sendPlatformMessageWait(deviceID string, session RegisterSession, xmlBody string, timeout time.Duration) (*SipMessage, error) {
	callID := randToken(16)
	tag := randToken(8)
	branch := "z9hG4bK" + randToken(10)
	uri := "sip:" + deviceID + "@" + r.cfg.ServerID
	localAddr := fmt.Sprintf("%s:%d", r.cfg.Host, r.LocalPort())
	cseq := r.nextPlatformCSeq()

	viaProto := "UDP"
	if strings.EqualFold(session.Transport, "tcp") {
		viaProto = "TCP"
	}

	msg := NewRequest("MESSAGE", uri, callID, cseq)
	msg.Headers.Set("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=%s", viaProto, localAddr, branch))
	msg.Headers.Set("From", fmt.Sprintf("<sip:%s@%s>;tag=%s", r.cfg.ServerID, r.cfg.ServerID, tag))
	msg.Headers.Set("To", fmt.Sprintf("<sip:%s@%s>", deviceID, r.cfg.ServerID))
	msg.Headers.Set("Max-Forwards", "70")
	msg.Headers.Set("Contact", fmt.Sprintf("<sip:%s@%s>", r.cfg.ServerID, localAddr))
	msg.Headers.Set("Content-Type", "Application/MANSCDP+xml")
	msg.Body = []byte(xmlBody)

	t := r.transportFor(session.Transport)
	if t == nil {
		return nil, fmt.Errorf("传输层不可用")
	}
	target := session.LastRegisterAddr

	if timeout <= 0 {
		if err := t.Send(msg.Bytes(), target); err != nil {
			return nil, fmt.Errorf("发送失败: %w", err)
		}
		r.ev.RecordOut(t.Protocol(), target, msg.Bytes())
		return nil, nil
	}

	// 先注册应答通道再发送，避免响应早于通道就绪被丢弃。
	respCh := make(chan *SipMessage, 4)
	r.mu.Lock()
	if r.pendingMessages == nil {
		r.pendingMessages = map[string]chan *SipMessage{}
	}
	r.pendingMessages[callID] = respCh
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pendingMessages, callID)
		r.mu.Unlock()
	}()

	if err := t.Send(msg.Bytes(), target); err != nil {
		return nil, fmt.Errorf("发送失败: %w", err)
	}
	r.ev.RecordOut(t.Protocol(), target, msg.Bytes())

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case resp := <-respCh:
			if resp.StatusCode >= 100 && resp.StatusCode < 200 {
				continue // 跳过临时响应
			}
			return resp, nil
		case <-timer.C:
			return nil, fmt.Errorf("等待设备应答超时（%s）", timeout)
		case <-r.stopCh:
			return nil, fmt.Errorf("已停止")
		}
	}
}
