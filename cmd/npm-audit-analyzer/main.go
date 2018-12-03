package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/template"

	npmaudit "github.com/erizocosmico/npm-audit-analyzer"
	"google.golang.org/grpc"
	"gopkg.in/src-d/go-log.v1"
	"gopkg.in/src-d/lookout-sdk.v0/pb"
)

type analyzer struct{}

const (
	port    = 2020
	version = "alpha"

	pkgFile  = "package.json"
	lockFile = "package-lock.json"
)

var dataSrvAddr string
var tpl *template.Template

func init() {
	var err error
	dataSrvAddr, err = pb.ToGoGrpcAddress("ipv4://localhost:10301")
	if err != nil {
		panic(err)
	}

	tpl, err = template.New("npmaudit").Parse(messageTpl)
	if err != nil {
		panic(fmt.Errorf("unable to parse comment template: %s", err))
	}
}

func (*analyzer) NotifyReviewEvent(ctx context.Context, review *pb.ReviewEvent) (*pb.EventResponse, error) {
	log.Infof("got review request %v", review)

	conn, err := pb.DialContext(ctx, dataSrvAddr, grpc.WithInsecure())
	if err != nil {
		log.Errorf(err, "failed to connect to DataServer at %s", dataSrvAddr)
		return nil, err
	}
	defer conn.Close()

	cli := pb.NewDataClient(conn)
	changes, err := cli.GetChanges(ctx, &pb.ChangesRequest{
		Head:            &review.Head,
		Base:            &review.Base,
		WantContents:    true,
		WantUAST:        false,
		ExcludeVendored: true,
	})
	if err != nil {
		log.Errorf(err, "GetChanges from DataServer %s failed", dataSrvAddr)
		return nil, err
	}

	var packagesByRoot = make(map[string][2][]byte)
	for {
		change, err := changes.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}

			log.Errorf(err, "GetChanges from DataServer %s failed", dataSrvAddr)
			return nil, err
		}

		if change.Head == nil {
			continue
		}

		root := filepath.Dir(change.Head.Path)
		var idx int
		switch filepath.Base(change.Head.Path) {
		case pkgFile:
			idx = 0
		case lockFile:
			idx = 1
		default:
			continue
		}

		pkg := packagesByRoot[root]
		pkg[idx] = change.Head.Content
		packagesByRoot[root] = pkg
	}

	var comments []*pb.Comment
	for root, pkg := range packagesByRoot {
		packageJSON, packageLock := pkg[0], pkg[1]
		if len(packageJSON) == 0 || len(packageLock) == 0 {
			// only roots with both package.json and package-lock.json are
			// supported, as npm audit requires package-lock.json
			continue
		}

		vulns, err := npmaudit.Scan(ctx, packageJSON, packageLock)
		if err != nil {
			log.Errorf(err, "unable to scan vulnerabilities from %s", root)
			continue
		}

		file := filepath.Join(root, pkgFile)
		comments = append(comments, toComments(file, vulns)...)
	}

	return &pb.EventResponse{
		AnalyzerVersion: version,
		Comments:        comments,
	}, nil
}

func toComments(file string, vulns []npmaudit.Vulnerability) []*pb.Comment {
	var result []*pb.Comment

	for _, v := range vulns {
		result = append(result, &pb.Comment{
			File: file,
			Line: int32(v.Line),
			Text: vulnerabilityMessage(v),
		})
	}

	return result
}

const messageTpl = `A vulnerability has been detected on your ` + "`package.json`" + `.

* **Vulnerable dependency:** ` + "`{{.Package}}`" + `
{{- if ne .Package .Path}}
* **Dependency path:** ` + "`{{.Path}}`" + `{{end}}
* **Dev dependency:** {{if .Dev}}Yes{{else}}No{{end}}
* **Severity:** {{.Severity}}
* **Installed version:** ` + "`{{.TargetVersion}}`" + `
* **Current constraint:** ` + "`{{.Constraint}}`" + `
* **Vulnerable versions:** ` + "`{{.VulnerableVersions}}`" + `
* **Patched versions:** ` + "`{{.PatchedVersions}}`" + `
* **Recommendation:** {{.Recommendation}}

{{.Overview}}

[More info about this vulnerability]({{.URL}})
`

func vulnerabilityMessage(v npmaudit.Vulnerability) string {
	var buf bytes.Buffer
	_ = tpl.Execute(&buf, v)
	return buf.String()
}

func (*analyzer) NotifyPushEvent(context.Context, *pb.PushEvent) (*pb.EventResponse, error) {
	return new(pb.EventResponse), nil
}

func main() {
	l, err := pb.Listen(fmt.Sprintf("ipv4://0.0.0.0:%d", port))
	if err != nil {
		log.Errorf(err, "failed to listen on port: %d", port)
		os.Exit(1)
	}

	s := grpc.NewServer()
	pb.RegisterAnalyzerServer(s, new(analyzer))
	log.Infof("starting gRPC Analyzer server at port %d", port)
	s.Serve(l)
}
