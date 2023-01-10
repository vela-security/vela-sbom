package pkg

func (m AlpmMetadata) SHA1() string            { return "" }
func (m CargoMetadata) SHA1() string           { return "" }
func (m DotnetDepsMetadata) SHA1() string      { return m.Sha512 }
func (m PhpComposerJSONMetadata) SHA1() string { return m.Dist.Shasum }

func (m ApkMetadata) SHA1() string {
	for _, file := range m.Files {
		if file.Digest.Algorithm == "sha1" {
			return file.Digest.Value
		}
	}
	return ""
}

func (m DpkgMetadata) SHA1() string {
	for _, file := range m.Files {
		if file.Digest.Algorithm == "sha1" {
			return file.Digest.Value
		}
	}
	return ""
}

func (m JavaMetadata) SHA1() string {
	for _, digest := range m.ArchiveDigests {
		if digest.Algorithm == "sha1" {
			return digest.Value
		}
	}
	return ""
}
func (m PythonPackageMetadata) SHA1() string {
	for _, file := range m.Files {
		if file.Digest.Algorithm == "sha1" {
			return file.Digest.Value
		}
	}
	return ""
}

func (m RpmdbMetadata) SHA1() string {
	for _, file := range m.Files {
		if file.Digest.Algorithm == "sha1" {
			return file.Digest.Value
		}
	}

	return ""
}
