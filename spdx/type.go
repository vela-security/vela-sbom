package spdx

type sdxEx struct {
	Category string `json:"referenceCategory"`
	Locator  string `json:"referenceLocator"`
	Type     string `json:"referenceType"`
}

type sdxPackage struct {
	ID string `json:"SPDXID"`

	Checksums []struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	} `json:"checksums"`

	Location         string  `json:"downloadLocation"`
	External         []sdxEx `json:"externalRefs"`
	FilesAnalyzed    bool    `json:"filesAnalyzed"`
	LicenseConcluded string  `json:"licenseConcluded"`
	LicenseDeclared  string  `json:"licenseDeclared"`
	Name             string  `json:"name"`
	Source           string  `json:"sourceInfo"`
	Version          string  `json:"versionInfo"`
}

type Spdx struct {
	ID string `json:"SPDXID"`

	Checksum struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	} `json:"checksum"`

	Creation struct {
		Created            string   `json:"created"`
		Creators           []string `json:"creators"`
		LicenseListVersion string   `json:"licenseListVersion"`
	} `json:"creationInfo"`

	DataLicense       string       `json:"dataLicense"`
	DocumentNamespace string       `json:"documentNamespace"`
	Name              string       `json:"name"`
	SpdxVersion       string       `json:"spdxVersion"`
	Packages          []sdxPackage `json:"packages"`
}
