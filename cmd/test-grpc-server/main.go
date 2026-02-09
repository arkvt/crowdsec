package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/crowdsecurity/crowdsec/pkg/probesync/pb"
)

type testServer struct {
	pb.UnimplementedProbeSyncServer
	logFile         string
	commandsSent    bool
	stream          pb.ProbeSync_ConnectServer
	sendCommands    bool
	commandInterval time.Duration
}

func (s *testServer) Connect(stream pb.ProbeSync_ConnectServer) error {
	// 获取认证元数据
	md, ok := metadata.FromIncomingContext(stream.Context())
	if ok {
		log.Printf("📝 Incoming Metadata:")
		for k, v := range md {
			log.Printf("  %s: %v", k, v)
		}
	}

	log.Println("🔌 Client connected")

	// 发送心跳确认
	go func() {
		time.Sleep(1 * time.Second)
		ack := &pb.BackendMessage{
			Payload: &pb.BackendMessage_HeartbeatAck{
				HeartbeatAck: &pb.HeartbeatAck{
					ServerTime:            time.Now().UTC().Format(time.RFC3339),
					ConfigUpdateAvailable: false,
				},
			},
		}
		if err := stream.Send(ack); err != nil {
			log.Printf("❌ Failed to send heartbeat ack: %v", err)
		} else {
			log.Println("✅ Sent HeartbeatAck")
		}
	}()

	// 接收消息
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			log.Println("📪 Stream closed by client (EOF)")
			return nil
		}
		if err != nil {
			log.Printf("❌ Receive error: %v", err)
			return err
		}

		s.handleMessage(msg, stream)
	}
}

func (s *testServer) handleMessage(msg *pb.ProbeMessage, stream pb.ProbeSync_ConnectServer) {
	log.Println("\n================================================================================")
	log.Printf("📨 Received ProbeMessage from probe_id: %s", msg.ProbeId)

	switch payload := msg.Payload.(type) {
	case *pb.ProbeMessage_Heartbeat:
		s.handleHeartbeat(msg.ProbeId, payload.Heartbeat, stream)

	case *pb.ProbeMessage_DataBatch:
		s.handleDataBatch(msg.ProbeId, payload.DataBatch, stream)

	case *pb.ProbeMessage_CommandAck:
		s.handleCommandAck(msg.ProbeId, payload.CommandAck)

	default:
		log.Printf("⚠️  Unknown payload type: %T", payload)
	}
}

func (s *testServer) handleHeartbeat(probeID string, hb *pb.Heartbeat, stream pb.ProbeSync_ConnectServer) {
	log.Println("💓 Heartbeat Message:")
	log.Printf("  Type: Heartbeat")
	log.Printf("  ProbeID: %s", probeID)
	log.Printf("  Timestamp: %s", hb.Timestamp)

	if hb.Status != nil {
		log.Println("  Status:")
		log.Printf("    Version: %s", hb.Status.Version)
		log.Printf("    UptimeSeconds: %d", hb.Status.UptimeSeconds)
		log.Printf("    PendingAccessLogs: %d", hb.Status.PendingAccessLogs)
		log.Printf("    PendingAlerts: %d", hb.Status.PendingAlerts)
		log.Printf("    PendingDecisions: %d", hb.Status.PendingDecisions)
	}

	// 发送 HeartbeatAck
	ack := &pb.BackendMessage{
		Payload: &pb.BackendMessage_HeartbeatAck{
			HeartbeatAck: &pb.HeartbeatAck{
				ServerTime:            time.Now().UTC().Format(time.RFC3339),
				ConfigUpdateAvailable: false,
			},
		},
	}
	if err := stream.Send(ack); err != nil {
		log.Printf("❌ Failed to send heartbeat ack: %v", err)
	}

	// 首次心跳后发送测试指令
	if s.sendCommands && !s.commandsSent {
		if hb.Status == nil {
			log.Println("⚠️ send-commands 已开启，但 Heartbeat.Status 为空，仍尝试发送测试指令")
		} else if hb.Status.UptimeSeconds <= 0 {
			log.Printf("⚠️ send-commands 已开启，但 UptimeSeconds=%d，仍尝试发送测试指令", hb.Status.UptimeSeconds)
		}
		s.commandsSent = true
		s.stream = stream
		go s.sendTestCommands(probeID)
	}
}

func (s *testServer) handleDataBatch(probeID string, batch *pb.DataBatch, stream pb.ProbeSync_ConnectServer) {
	log.Println("📦 DataBatch Message:")
	log.Printf("  Type: DataBatch")
	log.Printf("  ProbeID: %s", probeID)
	log.Printf("  BatchID: %s", batch.BatchId)
	log.Printf("  CursorFrom: %d", batch.CursorFrom)
	log.Printf("  CursorTo: %d", batch.CursorTo)
	log.Printf("  Timestamp: %s", batch.Timestamp)

	payloadType := "unknown"
	var payloadJSON []byte
	switch payload := batch.Payload.(type) {
	case *pb.DataBatch_CaddyLogs:
		payloadType = "caddy_logs"
		payloadJSON, _ = protojson.Marshal(payload.CaddyLogs)
	case *pb.DataBatch_Alerts:
		payloadType = "alerts"
		payloadJSON, _ = protojson.Marshal(payload.Alerts)
	case *pb.DataBatch_Decisions:
		payloadType = "decisions"
		payloadJSON, _ = protojson.Marshal(payload.Decisions)
	case *pb.DataBatch_HostActivityLogs:
		payloadType = "host_activity_logs"
		payloadJSON, _ = protojson.Marshal(payload.HostActivityLogs)
	case *pb.DataBatch_HostProtectionLogs:
		payloadType = "host_protection_logs"
		payloadJSON, _ = protojson.Marshal(payload.HostProtectionLogs)
	default:
		log.Printf("  Payload: <unknown>")
	}

	if len(payloadJSON) > 0 {
		json.MarshalIndent(json.RawMessage(payloadJSON), "    ", "  ")
		log.Printf("  Payload (%s):\n", payloadType)
	}

	// 发送 BatchAck
	batchAck := &pb.BackendMessage{
		Payload: &pb.BackendMessage_BatchAck{
			BatchAck: &pb.BatchAck{
				BatchId: batch.BatchId,
				Status:  pb.AckStatus_ACK_STATUS_OK,
				Error:   "",
			},
		},
	}
	if err := stream.Send(batchAck); err != nil {
		log.Printf("❌ Failed to send batch ack: %v", err)
	} else {
		log.Printf("✅ Sent BatchAck for %s", batch.BatchId)
	}
}

func (s *testServer) handleCommandAck(probeID string, ack *pb.CommandAck) {
	log.Println("✔️  CommandAck Message:")
	log.Printf("  Type: CommandAck")
	log.Printf("  ProbeID: %s", probeID)
	log.Printf("  CommandID: %s", ack.CommandId)
	log.Printf("  Status: %s (%d)", ack.Status.String(), ack.Status)
	log.Printf("  Result: %s", ack.Result)
	if ack.Error != "" {
		log.Printf("  Error: %s", ack.Error)
	}
}

func saveToFile(filename string, data []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sendTestCommands 发送一系列测试指令
func (s *testServer) sendTestCommands(probeID string) {
	log.Println("\n🎯 Starting to send test commands to probe...")
	time.Sleep(s.commandInterval)

	commands := []struct {
		name    string
		cmdType pb.CommandType
		params  string
	}{
		{
			name:    "PING",
			cmdType: pb.COMMAND_TYPE_PING,
			params:  "{}",
		},
		{
			name:    "ADD_DECISION (ban IP 192.0.2.100)",
			cmdType: pb.COMMAND_TYPE_ADD_DECISION,
			params:  `{"value":"192.0.2.100","scope":"ip","type":"ban","duration":"4h","reason":"test ban from gRPC server"}`,
		},
		{
			name:    "ADD_WHITELIST (whitelist IP 203.0.113.50)",
			cmdType: pb.COMMAND_TYPE_ADD_WHITELIST,
			params:  `{"ip":"203.0.113.50","duration":"24h","reason":"test whitelist from gRPC server"}`,
		},
		{
			name:    "REMOVE_DECISION (unban 192.0.2.100)",
			cmdType: pb.COMMAND_TYPE_REMOVE_DECISION,
			params:  `{"value":"192.0.2.100","scope":"ip"}`,
		},
		{
			name:    "REMOVE_WHITELIST (remove 203.0.113.50)",
			cmdType: pb.COMMAND_TYPE_REMOVE_WHITELIST,
			params:  `{"ip":"203.0.113.50"}`,
		},
		{
			name:    "HOST_LOCK_PATH (lock C:\\read\\test.txt)",
			cmdType: pb.COMMAND_TYPE_HOST_LOCK_PATH,
			params:  `{"path":"C:\\read\\test.txt"}`,
		},
		{
			name:    "HOST_QUERY_STATUS (C:\\read\\test.txt)",
			cmdType: pb.COMMAND_TYPE_HOST_QUERY_STATUS,
			params:  `{"path":"C:\\read\\test.txt"}`,
		},
		{
			name:    "HOST_TEMP_UNLOCK_PATH (30s for C:\\read\\test.txt)",
			cmdType: pb.COMMAND_TYPE_HOST_TEMP_UNLOCK_PATH,
			params:  `{"path":"C:\\read\\test.txt","duration_seconds":30}`,
		},
		{
			name:    "HOST_APPLY_POLICY (re-apply locks)",
			cmdType: pb.COMMAND_TYPE_HOST_APPLY_POLICY,
			params:  `{}`,
		},
	}

	for i, cmd := range commands {
		commandID := fmt.Sprintf("test-cmd-%d-%d", time.Now().Unix(), i+1)

		log.Printf("\n📤 Sending Command #%d: %s", i+1, cmd.name)
		log.Printf("  CommandID: %s", commandID)
		log.Printf("  Type: %s (%d)", cmd.cmdType.String(), cmd.cmdType)
		log.Printf("  Params: %s", cmd.params)

		command := &pb.BackendMessage{
			Payload: &pb.BackendMessage_Command{
				Command: &pb.Command{
					Id:        commandID,
					Type:      cmd.cmdType,
					Params:    []byte(cmd.params),
					CreatedAt: time.Now().UTC().Format(time.RFC3339),
					ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
				},
			},
		}

		if err := s.stream.Send(command); err != nil {
			log.Printf("❌ Failed to send command %s: %v", cmd.name, err)
			return
		}

		log.Printf("✅ Command sent: %s", cmd.name)

		// 等待一段时间再发下一条
		if i < len(commands)-1 {
			time.Sleep(s.commandInterval)
		}
	}

	log.Println("\n✅ All test commands sent. Waiting for CommandAck responses...")
}

func main() {
	port := flag.Int("port", 50051, "Server port")
	sendCommands := flag.Bool("send-commands", false, "Send test commands to probe after first heartbeat")
	commandInterval := flag.Duration("command-interval", 3*time.Second, "Interval between commands")
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterProbeSyncServer(grpcServer, &testServer{
		sendCommands:    *sendCommands,
		commandInterval: *commandInterval,
	})

	log.Printf("🚀 Test gRPC Server listening on :%d", *port)
	log.Println("📝 This server will capture and display all ProbeMessage data")
	if *sendCommands {
		log.Println("🎯 Command sending enabled - will send test commands after first heartbeat")
		log.Printf("⏱️  Command interval: %v", *commandInterval)
	}
	log.Println("================================================================================")

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
