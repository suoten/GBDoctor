package sip

import (
	"fmt"
	"strings"
	"time"
)

// PTZFact 为 PTZ 控制环节事实。
type PTZFact struct {
	DeviceID   string
	ChannelID  string
	Command    string // PTZ 指令十六进制串
	StatusCode int
	Source     string
	TS         time.Time
	ErrCode    string
	ErrDetail  string
}

// PTZControlXML 构造 PTZ 控制报文 XML。
func PTZControlXML(deviceID, channelID, ptzCmd string, sn int) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Control>
<CmdType>DeviceControl</CmdType>
<SN>%d</SN>
<DeviceID>%s</DeviceID>
<PTZCmd>%s</PTZCmd>
</Control>`, sn, deviceID, ptzCmd)
}

// VoiceFact 为语音对讲环节事实。
type VoiceFact struct {
	DeviceID   string
	ChannelID  string
	StatusCode int
	SDP        *SDPInfo
	Direction  string // sendrecv / sendonly / recvonly
	TS         time.Time
	ErrDetail  string
}

// BuildVoiceInviteSDP 构造语音对讲 INVITE 请求的 SDP。
// 与视频点播不同，语音对讲使用 a=sendrecv 表示双向音频。
func BuildVoiceInviteSDP(channelID, platformIP string, mediaPort int, ssrc string) string {
	return fmt.Sprintf("v=0\r\n"+
		"o=%s 0 0 IN IP4 %s\r\n"+
		"s=Playback\r\n"+
		"c=IN IP4 %s\r\n"+
		"t=0 0\r\n"+
		"m=audio %d RTP/AVP 8\r\n"+
		"a=rtpmap:8 PCMA/8000\r\n"+
		"a=sendrecv\r\n"+
		"y=%s\r\n", channelID, platformIP, platformIP, mediaPort, ssrc)
}

// ParsePTZCommand 解析 PTZ 指令字节。
// 国标 PTZ 指令格式：A5 + 0F + 01 + cmd1 + cmd2 + pan + tilt + zoom + B1
// 返回 (cmd1, cmd2, 说明)。
func ParsePTZCommand(hexCmd string) (byte, byte, string) {
	if len(hexCmd) < 16 {
		return 0, 0, "指令长度不足"
	}
	// 去除空格
	hex := strings.ReplaceAll(hexCmd, " ", "")
	if len(hex) < 16 {
		return 0, 0, "指令长度不足"
	}
	// 解析 cmd1 (第 4-5 位) 和 cmd2 (第 6-7 位)
	cmd1 := parseHexByte(hex[6:8])
	cmd2 := parseHexByte(hex[8:10])

	desc := describePTZ(cmd1, cmd2)
	return cmd1, cmd2, desc
}

func parseHexByte(s string) byte {
	var v byte
	for i := 0; i < len(s) && i < 2; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			v = v*16 + (c - '0')
		case c >= 'a' && c <= 'f':
			v = v*16 + (c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v = v*16 + (c - 'A' + 10)
		}
	}
	return v
}

// describePTZ 根据 cmd1/cmd2 位描述 PTZ 动作。
func describePTZ(cmd1, cmd2 byte) string {
	var actions []string
	// cmd1 高 4 位为水平方向，低 4 位为垂直方向
	horizontal := cmd1 >> 4
	vertical := cmd1 & 0x0f
	// cmd2 高 4 位为变倍，低 4 位为其他
	zoom := cmd2 >> 4

	if horizontal == 1 {
		actions = append(actions, "右转")
	} else if horizontal == 2 {
		actions = append(actions, "左转")
	}
	if vertical == 1 {
		actions = append(actions, "下转")
	} else if vertical == 2 {
		actions = append(actions, "上转")
	}
	if zoom == 1 {
		actions = append(actions, "缩小")
	} else if zoom == 2 {
		actions = append(actions, "放大")
	}
	if len(actions) == 0 {
		return "停止"
	}
	return strings.Join(actions, "+")
}

// PTZValidations 校验 PTZ 指令合规性。
func PTZValidations(cmd string) []Deviation {
	var devs []Deviation
	if len(cmd) < 16 {
		devs = append(devs, Deviation{
			Kind:   "ptz_short",
			Detail: fmt.Sprintf("PTZ 指令长度=%d，国标要求 16 位十六进制", len(cmd)),
		})
		return devs
	}
	if !strings.HasPrefix(strings.ToUpper(cmd), "A5") {
		devs = append(devs, Deviation{
			Kind:   "ptz_bad_prefix",
			Detail: "PTZ 指令应以 A5 开头",
		})
	}
	// 校验校验位（最后两位应为 B1）
	if len(cmd) >= 18 {
		end := strings.ToUpper(cmd[len(cmd)-2:])
		if end != "B1" {
			devs = append(devs, Deviation{
				Kind:   "ptz_bad_checksum",
				Detail: fmt.Sprintf("PTZ 指令末尾=%s，国标要求 B1", end),
			})
		}
	}
	return devs
}
