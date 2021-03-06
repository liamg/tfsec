package parser

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"

	"github.com/hashicorp/hcl/v2/hclparse"

	"github.com/hashicorp/hcl/v2"
)

var knownFiles = make(map[string]struct{})

func CountFiles() int {
	return len(knownFiles)
}

func LoadDirectory(fullPath string, stopOnHCLError bool) ([]*hcl.File, error) {

	t := metrics.Start(metrics.DiskIO)
	defer t.Stop()

	hclParser := hclparse.NewParser()

	fileInfos, err := ioutil.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}

	for _, info := range fileInfos {
		if info.IsDir() {
			continue
		}

		var parseFunc func(filename string) (*hcl.File, hcl.Diagnostics)

		switch true {
		case strings.HasSuffix(info.Name(), ".tf"):
			parseFunc = hclParser.ParseHCLFile
		case strings.HasSuffix(info.Name(), ".tf.json"):
			parseFunc = hclParser.ParseJSONFile
		default:
			continue
		}

		path := filepath.Join(fullPath, info.Name())
		_, diag := parseFunc(path)
		if diag != nil && diag.HasErrors() {
			if stopOnHCLError {
				return nil, diag
			}
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: HCL error: %s\n", diag)
			continue
		}

		knownFiles[path] = struct{}{}
	}

	var files []*hcl.File
	for _, file := range hclParser.Files() {
		files = append(files, file)
	}

	return files, nil
}
