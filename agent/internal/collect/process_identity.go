package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"open-edr-mdr-agent/agent/internal/agentapi"
)

func ApplyProcessIdentity(event *agentapi.NormalizedEvent, bootID string) {
	if event == nil || event.ProcessID == "" {
		return
	}
	if event.BootID == "" {
		event.BootID = bootID
	}
	if event.ImagePath == "" {
		if image, _ := event.Raw["image"].(string); image != "" {
			event.ImagePath = image
		}
	}
	if event.ProcessEntityID == "" {
		event.ProcessEntityID = processEntityID(event.Host, event.BootID, event.ProcessID, event.ProcessCreateTime, event.ImagePath, event.ImageHash)
	}
	if event.ProcessIdentityConfidence == "" {
		event.ProcessIdentityConfidence = processIdentityConfidence(event)
	}
	if event.ParentProcessID == "" || event.ParentProcessEntityID != "" {
		return
	}
	parentCreate, _ := event.Raw["parent_process_create_time"].(string)
	parentImage, _ := event.Raw["parent_image_path"].(string)
	parentHash, _ := event.Raw["parent_image_hash"].(string)
	if parentCreate != "" && (parentImage != "" || parentHash != "") {
		event.ParentProcessEntityID = processEntityID(event.Host, event.BootID, event.ParentProcessID, parentCreate, parentImage, parentHash)
		return
	}
	if event.MissingParentReason == "" {
		event.MissingParentReason = "parent_identity_unavailable"
	}
}

func processEntityID(host, bootID, pid, createTime, imagePath, imageHash string) string {
	parts := []string{host, bootID, pid, createTime, strings.ToLower(imagePath), strings.ToLower(imageHash)}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "peid:" + hex.EncodeToString(sum[:16])
}

func processIdentityConfidence(event *agentapi.NormalizedEvent) string {
	if event.ProcessCreateTime != "" && (event.ImagePath != "" || event.ImageHash != "") {
		return "high"
	}
	if event.ProcessCreateTime != "" {
		return "medium"
	}
	return "low"
}
