package pusher

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// State 负责游标持久化与原子写入
type State struct {
	path   string
	mu     sync.RWMutex
	data   StateData
	logger *log.Entry
}

// StateData 保存游标与同步时间戳
type StateData struct {
	Cursors  map[string]string `json:"cursors"`
	LastSync map[string]string `json:"last_sync"`
}

// NewState 创建状态管理器
func NewState(path string, logger *log.Entry) (*State, error) {
	s := &State{
		path:   path,
		logger: logger,
		data: StateData{
			Cursors:  make(map[string]string),
			LastSync: make(map[string]string),
		},
	}

	// 确保目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	// 尝试加载已有状态
	if err := s.load(); err != nil {
		// 非致命错误：使用空状态
		if logger != nil {
			logger.WithError(err).Warn("failed to load state, starting fresh")
		}
	}

	return s, nil
}

// load 从磁盘读取状态
func (s *State) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 空状态启动
		}
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := json.Unmarshal(data, &s.data); err != nil {
		return fmt.Errorf("unmarshal state: %w", err)
	}

	// 确保 map 初始化
	if s.data.Cursors == nil {
		s.data.Cursors = make(map[string]string)
	}
	if s.data.LastSync == nil {
		s.data.LastSync = make(map[string]string)
	}

	return nil
}

// Save 原子写入状态（临时文件 + rename）
func (s *State) Save() error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s.data, "", "  ")
	s.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	// 原子写入：临时文件 -> rename
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp state: %w", err)
	}

	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp) // 清理临时文件
		return fmt.Errorf("rename state: %w", err)
	}

	return nil
}

// GetCursor 获取游标
func (s *State) GetCursor(dataType string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Cursors[dataType]
}

// SetCursor 更新游标
func (s *State) SetCursor(dataType string, cursor string) {
	s.mu.Lock()
	s.data.Cursors[dataType] = cursor
	s.mu.Unlock()
}

// GetLastSync 获取最后同步时间
func (s *State) GetLastSync(dataType string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.LastSync[dataType]
}

// SetLastSync 更新最后同步时间
func (s *State) SetLastSync(dataType string, timestamp string) {
	s.mu.Lock()
	s.data.LastSync[dataType] = timestamp
	s.mu.Unlock()
}

// UpdateAndSave 原子更新游标并持久化
func (s *State) UpdateAndSave(dataType string, cursor string) error {
	s.mu.Lock()
	s.data.Cursors[dataType] = cursor
	s.data.LastSync[dataType] = time.Now().UTC().Format(time.RFC3339)
	s.mu.Unlock()

	return s.Save()
}
