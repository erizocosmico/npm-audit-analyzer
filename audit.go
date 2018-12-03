package npmaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/src-d/go-log.v1"
)

const (
	pkgFile  = "package.json"
	lockFile = "package-lock.json"
)

// Vulnerability contains all the data about a single vulnerability found in
// a package.json.
type Vulnerability struct {
	Line               int
	Dev                bool
	Package            string
	Path               string
	TargetVersion      string
	Constraint         string
	VulnerableVersions string
	PatchedVersions    string
	URL                string
	Recommendation     string
	Overview           string
	Severity           string
}

// Scan returns a list of vulnerabilities on the given package.json.
func Scan(ctx context.Context, packageJSON, packageLock []byte) ([]Vulnerability, error) {
	result, err := Audit(ctx, packageJSON, packageLock)
	if err != nil {
		return nil, err
	}

	pkg, err := parsePackage(packageJSON)
	if err != nil {
		return nil, err
	}

	return transform(result, pkg), nil
}

func transform(result *Result, pkg *pkg) []Vulnerability {
	var vulnerabilities []Vulnerability
	for _, a := range result.Advisories {
		v := Vulnerability{
			Package:            a.Module,
			VulnerableVersions: a.VulnerableVersions,
			PatchedVersions:    a.PatchedVersions,
			URL:                a.URL,
			Recommendation:     a.Recommendation,
			Severity:           a.Severity,
			Overview:           a.Overview,
		}

		for _, f := range a.Findings {
			v := v
			v.Dev = f.Dev
			v.TargetVersion = f.Version

			if len(f.Paths) != 1 {
				log.Warningf("finding with %d paths for %s", len(f.Paths), v.Package)
				continue
			}

			v.Path = f.Paths[0]
			root := strings.Split(v.Path, ">")[0]

			var info dependencyInfo
			var ok bool
			if v.Dev {
				info, ok = pkg.devDeps[root]
				if !ok {
					log.Warningf("root dep %s not found on devDependencies", root)
					continue
				}
			} else {
				info, ok = pkg.deps[root]
				if !ok {
					log.Warningf("root dep %s not found on dependencies", root)
					continue
				}
			}

			v.Constraint = info.constraint
			v.Line = info.line

			vulnerabilities = append(vulnerabilities, v)
		}
	}

	// Sort by path, severity and line
	sort.Slice(vulnerabilities, func(i, j int) bool {
		cmp := strings.Compare(vulnerabilities[i].Path, vulnerabilities[j].Path)
		if cmp < 0 {
			return true
		}

		cmp = strings.Compare(vulnerabilities[i].Severity, vulnerabilities[j].Severity)
		if cmp < 0 {
			return true
		}

		return vulnerabilities[i].Line-vulnerabilities[j].Line < 0
	})

	return vulnerabilities
}

// Result contains the result of npm audit.
type Result struct {
	Advisories map[string]Advisory `json:"advisories"`
}

// Finding contains the found dependencies that have vulnerabilities.
type Finding struct {
	Version string   `json:"version"`
	Paths   []string `json:"paths"`
	Dev     bool     `json:"dev"`
}

// Advisory represents any problem encountered by npm audit.
type Advisory struct {
	Title              string    `json:"title"`
	Module             string    `json:"module_name"`
	VulnerableVersions string    `json:"vulnerable_versions"`
	PatchedVersions    string    `json:"patched_versions"`
	Severity           string    `json:"severity"`
	URL                string    `json:"url"`
	Overview           string    `json:"overview"`
	Recommendation     string    `json:"recommendation"`
	Findings           []Finding `json:"findings"`
}

// Audit runs npm audit on the given package.json content.
func Audit(ctx context.Context, packageJSON, packageLock []byte) (*Result, error) {
	dir, err := ioutil.TempDir(os.TempDir(), "lookout-npm-audit-")
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = os.RemoveAll(dir)
	}()

	err = ioutil.WriteFile(filepath.Join(dir, pkgFile), packageJSON, 0777)
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(filepath.Join(dir, lockFile), packageLock, 0777)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	var errbuf bytes.Buffer

	npmPath, err := exec.LookPath("npm")
	if err != nil {
		return nil, fmt.Errorf("npm is not installed, but it is required for running this analyzer")
	}

	cmd := exec.CommandContext(ctx, npmPath, "audit", "--json")
	cmd.Dir = dir
	cmd.Stdout = &buf
	cmd.Stderr = &errbuf

	_ = cmd.Run()
	if errbuf.Len() > 0 {
		return nil, fmt.Errorf("unable to run audit: %s", errbuf.String())
	}

	var result Result
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("unable to parse audit output: %s", err)
	}

	return &result, nil
}
