/*
 * Anchore Engine API Server
 *
 * This is the Anchore Engine API. Provides the primary external API for users of the service.
 *
 * API version: 0.1.16
 * Contact: nurmi@anchore.com
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package external
// VulnerablePackageReference A record of a software item which is vulnerable or carries a fix for a vulnerability
type VulnerablePackageReference struct {
	// Package name
	Name string `json:"name,omitempty"`
	// A version for the package. If null, then references all versions
	Version *string `json:"version,omitempty"`
	// Package type (e.g. package, rpm, deb, apk, jar, npm, gem, ...)
	Type string `json:"type,omitempty"`
	// Severity of vulnerability affecting package
	Severity string `json:"severity,omitempty"`
	// Vulnerability namespace of affected package
	Namespace string `json:"namespace,omitempty"`
}
