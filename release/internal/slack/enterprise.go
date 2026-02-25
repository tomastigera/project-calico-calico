package slack

import (
	_ "embed"

	"github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
)

//go:embed templates/hashrelease-validated.json.gotmpl
var validatedMessageTemplateData string

type ValidatedHashreleaseMessageData struct {
	ReleaseName        string
	Product            string
	Stream             string
	ProductVersion     string
	OperatorVersion    string
	ReleaseType        string
	CIURL              string
	DocsURL            string
	ImageScanResultURL string
	TestResultURL      string
}

func UpdateHashreleaseAnnouncement(cfg *Config, resp *MessageResponse, msg *ValidatedHashreleaseMessageData) error {
	message, err := renderMessage(validatedMessageTemplateData, msg)
	if err != nil {
		logrus.WithError(err).Error("Failed to render message")
		return err
	}
	client := slack.New(cfg.Token, slack.OptionDebug(logrus.IsLevelEnabled(logrus.DebugLevel)))
	_, _, _, err = client.UpdateMessage(
		resp.Channel,
		resp.Timestamp,
		slack.MsgOptionBlocks(message...),
	)
	return err
}
