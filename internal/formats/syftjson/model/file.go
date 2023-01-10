package model

import (
	"github.com/vela-security/vela-sbom/detect/file"

	"github.com/vela-security/vela-sbom/detect/source"
)

type File struct {
	ID              string                `json:"id"`
	Location        source.Coordinates    `json:"location"`
	Metadata        *FileMetadataEntry    `json:"metadata,omitempty"`
	Contents        string                `json:"contents,omitempty"`
	Digests         []file.Digest         `json:"digests,omitempty"`
	Classifications []file.Classification `json:"classifications,omitempty"`
}

type FileMetadataEntry struct {
	Mode            int             `json:"mode"`
	Type            source.FileType `json:"type"`
	LinkDestination string          `json:"linkDestination,omitempty"`
	UserID          int             `json:"userID"`
	GroupID         int             `json:"groupID"`
	MIMEType        string          `json:"mimeType"`
}
