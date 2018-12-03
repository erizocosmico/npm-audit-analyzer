package npmaudit

import (
	"context"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

const testPkgJSON = `
{
	"name": "npm-audit-lookout-test",
	"version": "1.0.0",
	"description": "just a test for lookout and npm-audit",
	"main": "index.js",
	"scripts": {
	  "test": "echo \"Error: no test specified\" && exit 1"
	},
	"repository": {
	  "type": "git",
	  "url": "git+https://github.com/erizocosmico/npm-audit-lookout-test.git"
	},
	"author": "",
	"license": "ISC",
	"bugs": {
	  "url": "https://github.com/erizocosmico/npm-audit-lookout-test/issues"
	},
	"homepage": "https://github.com/erizocosmico/npm-audit-lookout-test#readme",
	"dependencies": {
	  "tough-cookie": "<=2.2.0",
	  "tough-cookie-filestore": "0.0.1"
	},
	"devDependencies": {
	  "serve-handler": "<5.0.3"
	}
}  
`
const testPkgLock = `
{
	"name": "npm-audit-lookout-test",
	"version": "1.0.0",
	"lockfileVersion": 1,
	"requires": true,
	"dependencies": {
	  "balanced-match": {
		"version": "1.0.0",
		"resolved": "https://registry.npmjs.org/balanced-match/-/balanced-match-1.0.0.tgz",
		"integrity": "sha1-ibTRmasr7kneFk6gK4nORi1xt2c=",
		"dev": true
	  },
	  "brace-expansion": {
		"version": "1.1.11",
		"resolved": "https://registry.npmjs.org/brace-expansion/-/brace-expansion-1.1.11.tgz",
		"integrity": "sha512-iCuPHDFgrHX7H2vEI/5xpz07zSHB00TpugqhmYtVmMO6518mCuRMoOYFldEBl0g187ufozdaHgWKcYFb61qGiA==",
		"dev": true,
		"requires": {
		  "balanced-match": "^1.0.0",
		  "concat-map": "0.0.1"
		}
	  },
	  "bytes": {
		"version": "3.0.0",
		"resolved": "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz",
		"integrity": "sha1-0ygVQE1olpn4Wk6k+odV3ROpYEg=",
		"dev": true
	  },
	  "concat-map": {
		"version": "0.0.1",
		"resolved": "https://registry.npmjs.org/concat-map/-/concat-map-0.0.1.tgz",
		"integrity": "sha1-2Klr13/Wjfd5OnMDajug1UBdR3s=",
		"dev": true
	  },
	  "content-disposition": {
		"version": "0.5.2",
		"resolved": "https://registry.npmjs.org/content-disposition/-/content-disposition-0.5.2.tgz",
		"integrity": "sha1-DPaLud318r55YcOoUXjLhdunjLQ=",
		"dev": true
	  },
	  "fast-url-parser": {
		"version": "1.1.3",
		"resolved": "https://registry.npmjs.org/fast-url-parser/-/fast-url-parser-1.1.3.tgz",
		"integrity": "sha1-9K8+qfNNiicc9YrSs3WfQx8LMY0=",
		"dev": true,
		"requires": {
		  "punycode": "^1.3.2"
		},
		"dependencies": {
		  "punycode": {
			"version": "1.4.1",
			"resolved": "https://registry.npmjs.org/punycode/-/punycode-1.4.1.tgz",
			"integrity": "sha1-wNWmOycYgArY4esPpSachN1BhF4=",
			"dev": true
		  }
		}
	  },
	  "glob-slash": {
		"version": "1.0.0",
		"resolved": "https://registry.npmjs.org/glob-slash/-/glob-slash-1.0.0.tgz",
		"integrity": "sha1-/lLvpDMjP3Si/mTHq7m8hIICq5U=",
		"dev": true
	  },
	  "mime-db": {
		"version": "1.33.0",
		"resolved": "http://registry.npmjs.org/mime-db/-/mime-db-1.33.0.tgz",
		"integrity": "sha512-BHJ/EKruNIqJf/QahvxwQZXKygOQ256myeN/Ew+THcAa5q+PjyTTMMeNQC4DZw5AwfvelsUrA6B67NKMqXDbzQ==",
		"dev": true
	  },
	  "mime-types": {
		"version": "2.1.18",
		"resolved": "http://registry.npmjs.org/mime-types/-/mime-types-2.1.18.tgz",
		"integrity": "sha512-lc/aahn+t4/SWV/qcmumYjymLsWfN3ELhpmVuUFjgsORruuZPVSwAQryq+HHGvO/SI2KVX26bx+En+zhM8g8hQ==",
		"dev": true,
		"requires": {
		  "mime-db": "~1.33.0"
		}
	  },
	  "minimatch": {
		"version": "3.0.4",
		"resolved": "https://registry.npmjs.org/minimatch/-/minimatch-3.0.4.tgz",
		"integrity": "sha512-yJHVQEhyqPLUTgt9B83PXu6W3rx4MvvHvSUvToogpwoGDOUQ+yDrR0HRot+yOCdCO7u4hX3pWft6kWBBcqh0UA==",
		"dev": true,
		"requires": {
		  "brace-expansion": "^1.1.7"
		}
	  },
	  "path-is-inside": {
		"version": "1.0.2",
		"resolved": "https://registry.npmjs.org/path-is-inside/-/path-is-inside-1.0.2.tgz",
		"integrity": "sha1-NlQX3t5EQw0cEa9hAn+s8HS9/FM=",
		"dev": true
	  },
	  "punycode": {
		"version": "2.1.1",
		"resolved": "https://registry.npmjs.org/punycode/-/punycode-2.1.1.tgz",
		"integrity": "sha512-XRsRjdf+j5ml+y/6GKHPZbrF/8p2Yga0JPtdqTIY2Xe5ohJPD9saDJJLPvp9+NSBprVvevdXZybnj2cv8OEd0A=="
	  },
	  "range-parser": {
		"version": "1.2.0",
		"resolved": "https://registry.npmjs.org/range-parser/-/range-parser-1.2.0.tgz",
		"integrity": "sha1-9JvmtIeJTdxA3MlKMi9hEJLgDV4=",
		"dev": true
	  },
	  "serve-handler": {
		"version": "5.0.2",
		"resolved": "https://registry.npmjs.org/serve-handler/-/serve-handler-5.0.2.tgz",
		"integrity": "sha512-sYhCyS//dNTTFHb8OlL/bFTTwACtlvnT2ybA0v1hTHxEnQ9tN1m2ifBIv4ozHUE8OjYCYUbuJ6No0enWdKHi5w==",
		"dev": true,
		"requires": {
		  "bytes": "3.0.0",
		  "content-disposition": "0.5.2",
		  "fast-url-parser": "1.1.3",
		  "glob-slash": "1.0.0",
		  "mime-types": "2.1.18",
		  "minimatch": "3.0.4",
		  "path-is-inside": "1.0.2",
		  "path-to-regexp": "2.2.1",
		  "range-parser": "1.2.0"
		},
		"dependencies": {
		  "path-to-regexp": {
			"version": "2.2.1",
			"resolved": "https://registry.npmjs.org/path-to-regexp/-/path-to-regexp-2.2.1.tgz",
			"integrity": "sha512-gu9bD6Ta5bwGrrU8muHzVOBFFREpp2iRkVfhBJahwJ6p6Xw20SjT0MxLnwkjOibQmGSYhiUnf2FLe7k+jcFmGQ==",
			"dev": true
		  }
		}
	  },
	  "tough-cookie": {
		"version": "2.2.0",
		"resolved": "http://registry.npmjs.org/tough-cookie/-/tough-cookie-2.2.0.tgz",
		"integrity": "sha1-1M5mEHXl/dt/IDQdP5kxpvu63eA="
	  },
	  "tough-cookie-filestore": {
		"version": "0.0.1",
		"resolved": "https://registry.npmjs.org/tough-cookie-filestore/-/tough-cookie-filestore-0.0.1.tgz",
		"integrity": "sha1-C/IwjtKTpQugcz7X1iiWAUhVcLY=",
		"requires": {
		  "tough-cookie": "~0.12.1"
		},
		"dependencies": {
		  "tough-cookie": {
			"version": "0.12.1",
			"resolved": "http://registry.npmjs.org/tough-cookie/-/tough-cookie-0.12.1.tgz",
			"integrity": "sha1-giDH4hq9WxPZaAQlS9WoHr8sfWI=",
			"requires": {
			  "punycode": ">=0.2.0"
			}
		  }
		}
	  }
	}
  }
`

func TestAudit(t *testing.T) {
	ensureNPMInstalled(t)
	require := require.New(t)

	result, err := Audit(context.Background(), []byte(testPkgJSON), []byte(testPkgLock))
	require.NoError(err)
	require.Len(result.Advisories, 2)
}

func TestScan(t *testing.T) {
	ensureNPMInstalled(t)
	require := require.New(t)

	result, err := Scan(context.Background(), []byte(testPkgJSON), []byte(testPkgLock))
	require.NoError(err)

	require.Len(result, 4)

	for i := range result {
		result[i].Overview = ""
	}

	require.Equal(expectedVulnerabilities, result)
}

var expectedVulnerabilities = []Vulnerability{
	{
		Line:               21,
		Dev:                false,
		Package:            "tough-cookie",
		Path:               "tough-cookie",
		TargetVersion:      "2.2.0",
		Constraint:         "<=2.2.0",
		VulnerableVersions: "<2.3.3",
		PatchedVersions:    ">=2.3.3",
		URL:                "https://npmjs.com/advisories/525",
		Recommendation:     "Update to version 2.3.3 or later.",
		Severity:           "high",
	},
	{
		Line:               22,
		Dev:                false,
		Package:            "tough-cookie",
		Path:               "tough-cookie-filestore>tough-cookie",
		TargetVersion:      "0.12.1",
		Constraint:         "0.0.1",
		VulnerableVersions: "<2.3.3",
		PatchedVersions:    ">=2.3.3",
		URL:                "https://npmjs.com/advisories/525",
		Recommendation:     "Update to version 2.3.3 or later.",
		Severity:           "high",
	},
	{
		Line:               21,
		Dev:                false,
		Package:            "tough-cookie",
		Path:               "tough-cookie",
		TargetVersion:      "2.2.0",
		Constraint:         "<=2.2.0",
		VulnerableVersions: ">=0.9.7 <=2.2.2",
		PatchedVersions:    ">=2.3.0",
		URL:                "https://npmjs.com/advisories/130",
		Recommendation:     "Update to version 2.3.0 or later.",
		Severity:           "moderate",
	},
	{
		Line:               22,
		Dev:                false,
		Package:            "tough-cookie",
		Path:               "tough-cookie-filestore>tough-cookie",
		TargetVersion:      "0.12.1",
		Constraint:         "0.0.1",
		VulnerableVersions: ">=0.9.7 <=2.2.2",
		PatchedVersions:    ">=2.3.0",
		URL:                "https://npmjs.com/advisories/130",
		Recommendation:     "Update to version 2.3.0 or later.",
		Severity:           "moderate",
	},
}

func ensureNPMInstalled(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm command is required to run this test")
	}
}
