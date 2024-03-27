/*
 * Copyright 2021-2024 JetBrains s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package platform

import (
	"context"
	"fmt"
	"github.com/owenrumney/go-sarif/v2/sarif"
	bbapi "github.com/reviewdog/go-bitbucket"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ReportRequest is an object that represent parameters used to create/update report
type ReportRequest struct {
	Owner      string
	Repository string
	Commit     string
	ReportID   string
	Type       string
	Title      string
	Reporter   string
	Result     string
	Details    string
	LogoURL    string
}

const (
	httpTimeout = time.Second * 10

	// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-reports/#api-repositories-workspace-repo-slug-commit-commit-reports-reportid-annotations-annotationid-put-request
	bitBucketHigh   = "HIGH"
	bitBucketMedium = "MEDIUM"
	bitBucketLow    = "LOW"
	bitBucketInfo   = "INFO"

	pipelineProxyURL = "http://localhost:29418"
	pipeProxyURL     = "http://host.docker.internal:29418"
)

// UnexpectedResponseError is triggered when we have unexpected response from Code Insights API
type UnexpectedResponseError struct {
	Code int
	Body []byte
}

func (e UnexpectedResponseError) Error() string {
	msg := fmt.Sprintf("received unexpected %d code from Bitbucket API", e.Code)

	if len(e.Body) > 0 {
		msg += " with message:\n" + string(e.Body)
	}

	return msg
}

var (
	toBitBucketSeverity = map[string]string{
		sarifError:     bitBucketHigh,
		sarifWarning:   bitBucketMedium,
		sarifNote:      bitBucketLow,
		qodanaCritical: bitBucketHigh,
		qodanaHigh:     bitBucketMedium,
		qodanaModerate: bitBucketMedium,
		qodanaLow:      bitBucketLow,
		qodanaInfo:     bitBucketInfo,
	}
)

// sendBitBucketReport sends annotations to BitBucket Code Insights
func sendBitBucketReport(annotations []bbapi.ReportAnnotation, toolName, cloudUrl, reportId string) error {
	err := putReport(annotations, toolName, cloudUrl, reportId)
	if err != nil {
		return err
	}

	if len(annotations) == 0 {
		log.Debug("No annotations to send to BitBucket Code Insights")
		return nil
	}

	totalAnnotations := len(annotations)
	if totalAnnotations > 1000 {
		totalAnnotations = 1000
		log.Debugf("Warning: Only first 1000 of %d annotations will be sent", len(annotations))
	}
	for i := 0; i < totalAnnotations; i += 100 {
		j := i + 100
		if j > totalAnnotations {
			j = totalAnnotations
		}
		err := sendChunk(annotations[i:j], reportId)
		if err != nil {
			return err
		}
	}
	return nil
}

// buildReport builds a report to be sent to BitBucket Code Insights
func buildReport(toolName string, annotations []bbapi.ReportAnnotation, cloudUrl string) bbapi.Report {
	data := bbapi.NewReport()
	data.SetTitle(toolName)
	data.SetReportType("BUG")
	data.SetReporter("JetBrains")
	data.SetLogoUrl("https://avatars.githubusercontent.com/u/139879315")
	data.SetResult("FAILED")
	data.SetDetails(fmt.Sprintf("%d new problems were found", len(annotations)))
	data.SetLink(cloudUrl)
	return *data
}

// buildAnnotation builds an annotation to be sent to BitBucket Code Insights
func buildAnnotation(result *sarif.Result, reportLink string) bbapi.ReportAnnotation {
	data := bbapi.NewReportAnnotation()
	bbSeverity, ok := toBitBucketSeverity[getSeverity(result)]
	if !ok {
		log.Debugf("Unknown SARIF severity: %s", getSeverity(result))
		bbSeverity = bitBucketLow
	}
	location := result.Locations[0].PhysicalLocation
	data.SetExternalId(getFingerprint(result))
	data.SetAnnotationType("CODE_SMELL")
	data.SetSummary(*result.RuleID)
	data.SetDetails(*result.Message.Text)
	data.SetSeverity(bbSeverity)
	data.SetLine(int32(*location.Region.StartLine))
	data.SetPath(*location.ArtifactLocation.URI)
	data.SetLink(reportLink)

	return *data
}

func putReport(annotations []bbapi.ReportAnnotation, toolName, cloudUrl, reportId string) error {
	client := getBitBucketClient()
	ctx := context.Background()
	ctx = buildBitBucketContext(ctx, "", "", "")
	_, resp, err := client.
		ReportsApi.CreateOrUpdateReport(ctx, getBitBucketRepoOwner(), getBitBucketRepoName(), getBitBucketCommit(), reportId).
		Body(buildReport(toolName, annotations, cloudUrl)).
		Execute()

	if err := checkAPIError(err, resp, http.StatusOK); err != nil {
		return fmt.Errorf("failed to create code insights report: %w", err)
	}

	return nil
}

// sendChunk sends a chunk of annotations to BitBucket Code Insights
func sendChunk(annotations []bbapi.ReportAnnotation, reportId string) error {
	client := getBitBucketClient()
	ctx := context.Background()
	ctx = buildBitBucketContext(ctx, "", "", "")
	_, resp, err := client.ReportsApi.
		BulkCreateOrUpdateAnnotations(ctx, getBitBucketRepoOwner(), getBitBucketRepoName(), getBitBucketCommit(), reportId).
		Body(annotations).
		Execute()
	if err := checkAPIError(err, resp, http.StatusOK); err != nil {
		return fmt.Errorf("failed to create code insights annotations: %w", err)
	}

	return nil
}

func getBitBucketClient() *bbapi.APIClient {
	config := bbapi.NewConfiguration()
	config.HTTPClient = &http.Client{
		Timeout: httpTimeout,
	}
	server := bbapi.ServerConfiguration{
		URL:         "https://api.bitbucket.org/2.0",
		Description: `HTTPS API endpoint`,
	}
	if isBitBucket() {
		var proxyURL *url.URL
		if isBitBucketPipe() {
			proxyURL, _ = url.Parse(pipeProxyURL)
		} else {
			proxyURL, _ = url.Parse(pipelineProxyURL)
		}
		config.HTTPClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
		server = bbapi.ServerConfiguration{
			URL:         "http://api.bitbucket.org/2.0",
			Description: `If called from Bitbucket Pipelines, using HTTP API endpoint and AuthProxy`,
		}
	}
	config.Servers = bbapi.ServerConfigurations{server}
	return bbapi.NewAPIClient(config)
}

func checkAPIError(err error, resp *http.Response, expectedCode int) error {
	if err != nil {
		return fmt.Errorf("bitbucket Cloud API error: %w", err)
	}

	if resp != nil && resp.StatusCode != expectedCode {
		body, _ := io.ReadAll(resp.Body)
		return UnexpectedResponseError{
			Code: resp.StatusCode,
			Body: body,
		}
	}

	return nil
}

// buildBitBucketContext builds context.Context used to call Bitbucket Cloud Code Insights API
func buildBitBucketContext(ctx context.Context, user, password, token string) context.Context {
	if user != "" && password != "" {
		ctx = withBasicAuth(ctx, user, password)
	}

	if token != "" {
		ctx = withAccessToken(ctx, token)
	}

	return ctx
}

// WithBasicAuth adds basic auth credentials to context
func withBasicAuth(ctx context.Context, username, password string) context.Context {
	return context.WithValue(ctx, bbapi.ContextBasicAuth,
		bbapi.BasicAuth{
			UserName: username,
			Password: password,
		})
}

// WithAccessToken adds basic auth credentials to context
func withAccessToken(ctx context.Context, accessToken string) context.Context {
	return context.WithValue(ctx, bbapi.ContextAccessToken, accessToken)
}
