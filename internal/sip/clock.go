package sip

import (
	"fmt"
	"time"
)

// ClockFact 为设备时间偏差检测事实。
type ClockFact struct {
	DeviceID     string
	DeviceTime   time.Time     // 设备上报的时间
	PlatformTime time.Time     // 平台接收时刻
	Offset       time.Duration // 偏差（正=设备快，负=设备慢）
	TS           time.Time
}

// CheckClockSync 通过设备 MESSAGE 中的时间戳字段计算时间偏差。
// 国标设备在某些 MESSAGE（如报警通知）中会携带 AlarmTime/TimeStamp 字段。
// 注意：设备上报的时间是本地墙上时间（无时区后缀），必须用本机时区解析；
// 若按 UTC 解析东八区设备会恒定产生 8 小时假偏差。
func CheckClockSync(deviceTimeStr, deviceID string) ClockFact {
	now := time.Now()
	fact := ClockFact{
		DeviceID:     deviceID,
		PlatformTime: now,
		TS:           now,
	}
	// 尝试多种国标时间格式（全部按本机时区解析）
	formats := []string{
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"20060102T150405",
		"20060102150405",
		time.RFC3339,
	}
	for _, fmtStr := range formats {
		if t, err := time.ParseInLocation(fmtStr, deviceTimeStr, time.Local); err == nil {
			fact.DeviceTime = t
			fact.Offset = t.Sub(now)
			break
		}
	}
	if fact.DeviceTime.IsZero() {
		// 无法解析，偏差设为 0
		fact.Offset = 0
	}
	return fact
}

// ClockOffsetConclusions 将时间偏差转换为人话结论列表。
func ClockOffsetConclusions(offset time.Duration) []string {
	var conclusions []string
	abs := offset
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs > 5*time.Minute:
		conclusions = append(conclusions, fmt.Sprintf("⚠️ 设备时间偏差 %s，严重超差（国标要求 <300s），可能导致注册异常/录像时间错乱", offset))
	case abs > 60*time.Second:
		conclusions = append(conclusions, fmt.Sprintf("⚠️ 设备时间偏差 %s，超过 60s，建议校时", offset))
	case abs > 10*time.Second:
		conclusions = append(conclusions, fmt.Sprintf("设备时间偏差 %s，轻微超差", offset))
	default:
		conclusions = append(conclusions, fmt.Sprintf("设备时间偏差 %s，正常", offset))
	}
	return conclusions
}

// PTZControl 发送 PTZ 控制指令（V1.1 功能），不等待应答。
// command 格式：A50F01XXYY...（国标 PTZ 控制字）。
func (r *DeviceSideRole) PTZControl(deviceID, channelID, command string) error {
	_, err := r.PTZControlWait(deviceID, channelID, command, 0)
	return err
}

// PTZControlWait 发送 PTZ 控制指令并等待设备确认应答。
// timeout <= 0 等同 PTZControl（fire-and-forget）。
// 设备回 200 OK 才能证明 PTZ 指令被接受；只看发送成功会产出假通过。
func (r *DeviceSideRole) PTZControlWait(deviceID, channelID, command string, timeout time.Duration) (*SipMessage, error) {
	session, ok := r.Session(deviceID)
	if !ok {
		return nil, fmt.Errorf("设备 %s 未注册", deviceID)
	}
	sn := int(time.Now().UnixNano() % 100000)
	xmlBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Control>
<CmdType>DeviceControl</CmdType>
<SN>%d</SN>
<DeviceID>%s</DeviceID>
<PTZCmd>%s</PTZCmd>
</Control>`, sn, deviceID, command)

	return r.sendPlatformMessageWait(deviceID, session, xmlBody, timeout)
}
