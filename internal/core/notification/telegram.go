package notification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type TelegramNotifier struct {
	botToken string
	chatID   string
	client   *http.Client
}

func NewTelegramNotifier(botToken, chatID string) *TelegramNotifier {
	return &TelegramNotifier{
		botToken: botToken,
		chatID:   chatID,
		client:   &http.Client{Timeout: 8 * time.Second},
	}
}

func (t *TelegramNotifier) IsConfigured() bool {
	return t.botToken != "" && t.chatID != ""
}

type tgMessagePayload struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode"`
}

func (t *TelegramNotifier) Send(text string) error {
	if !t.IsConfigured() {
		return fmt.Errorf("telegram bot token or chat ID is missing")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)
	payload := tgMessagePayload{
		ChatID:    t.chatID,
		Text:      text,
		ParseMode: "HTML",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	resp, err := t.client.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("send telegram request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Description string `json:"description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("telegram api error (%d): %s", resp.StatusCode, errResp.Description)
	}

	return nil
}

func (t *TelegramNotifier) SendTest() error {
	msg := "🐝 <b>Bee Panel - Notification Test</b>\n\n" +
		"✅ Telegram integration connected successfully!\n" +
		"⏰ Time: " + time.Now().Format("2006-01-02 15:04:05 MST") + "\n" +
		"🔒 Host: Bee Panel Control Plane"
	return t.Send(msg)
}
