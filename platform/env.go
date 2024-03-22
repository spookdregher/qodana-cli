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
    "bytes"
    "encoding/json"
    "fmt"
    cienvironment "github.com/cucumber/ci-environment/go"
    sarif2 "github.com/owenrumney/go-sarif/v2/sarif"
    log "github.com/sirupsen/logrus"
    "io"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "runtime"
    "strings"
)

const (
    QodanaLicenseOnlyToken = "QODANA_LICENSE_ONLY_TOKEN"
    QodanaRemoteUrl        = "QODANA_REMOTE_URL"
    QodanaDockerEnv        = "QODANA_DOCKER"
    QodanaToolEnv          = "QODANA_TOOL"
    QodanaConfEnv          = "QODANA_CONF"
    QodanaToken            = "QODANA_TOKEN"
    qodanaClearKeyring     = "QODANA_CLEAR_KEYRING"
    qodanaEnv              = "QODANA_ENV"
    qodanaJobUrl           = "QODANA_JOB_URL"
    QodanaBranch           = "QODANA_BRANCH"
    QodanaRevision         = "QODANA_REVISION"
    QodanaCliContainerName = "QODANA_CLI_CONTAINER_NAME"
    QodanaCliContainerKeep = "QODANA_CLI_CONTAINER_KEEP"
    QodanaCliUsePodman     = "QODANA_CLI_USE_PODMAN"
    QodanaDistEnv          = "QODANA_DIST"
    QodanaCorettoSdk       = "QODANA_CORETTO_SDK"
    AndroidSdkRoot         = "ANDROID_SDK_ROOT"
    QodanaLicense          = "QODANA_LICENSE"
    QodanaTreatAsRelease   = "QODANA_TREAT_AS_RELEASE"
    QodanaProjectIdHash    = "QODANA_PROJECT_ID_HASH"
    qodanaNugetUrl         = "QODANA_NUGET_URL"
    qodanaNugetUser        = "QODANA_NUGET_USER"
    qodanaNugetPassword    = "QODANA_NUGET_PASSWORD"
    qodanaNugetName        = "QODANA_NUGET_NAME"
    glCodeQualityReport    = "gl-code-quality-report.json"
)

// CCIssue represents a Code Climate (GitLab CodeQuality) issue
type CCIssue struct {
    CheckName   string   `json:"check_name"`
    Description string   `json:"description"`
    Fingerprint string   `json:"fingerprint"`
    Severity    string   `json:"severity"`
    Location    Location `json:"location"`
}

type Location struct {
    Path  string `json:"path"`
    Lines Line   `json:"lines"`
}

type Line struct {
    Begin int `json:"begin"`
}

// ExtractQodanaEnvironment extracts Qodana environment variables from the current environment.
func ExtractQodanaEnvironment(setEnvironmentFunc func(string, string)) {
    ci := cienvironment.DetectCIEnvironment()
    qEnv := "cli"
    if ci != nil {
        qEnv = strings.ReplaceAll(strings.ToLower(ci.Name), " ", "-")
        setEnvironmentFunc(qodanaJobUrl, validateJobUrl(ci.URL, qEnv))
        if ci.Git != nil {
            setEnvironmentFunc(QodanaRemoteUrl, validateRemoteUrl(ci.Git.Remote, qEnv))
            setEnvironmentFunc(QodanaBranch, validateBranch(ci.Git.Branch, qEnv))
            setEnvironmentFunc(QodanaRevision, ci.Git.Revision)
        }
        setEnvironmentFunc(qodanaNugetUrl, os.Getenv(qodanaNugetUrl))
        setEnvironmentFunc(qodanaNugetUser, os.Getenv(qodanaNugetUser))
        setEnvironmentFunc(qodanaNugetPassword, os.Getenv(qodanaNugetPassword))
        setEnvironmentFunc(qodanaNugetName, os.Getenv(qodanaNugetName))
    } else if space := os.Getenv("JB_SPACE_API_URL"); space != "" {
        qEnv = "space"
        setEnvironmentFunc(qodanaJobUrl, os.Getenv("JB_SPACE_EXECUTION_URL"))
        setEnvironmentFunc(QodanaRemoteUrl, getSpaceRemoteUrl())
        setEnvironmentFunc(QodanaBranch, os.Getenv("JB_SPACE_GIT_BRANCH"))
        setEnvironmentFunc(QodanaRevision, os.Getenv("JB_SPACE_GIT_REVISION"))
    }
    setEnvironmentFunc(qodanaEnv, fmt.Sprintf("%s:%s", qEnv, Version))
}

func validateRemoteUrl(remote string, qEnv string) string {
    if strings.HasPrefix(qEnv, "space") {
        return getSpaceRemoteUrl()
    }
    _, err := url.ParseRequestURI(remote)
    if remote == "" || err != nil {
        log.Warnf("Unable to parse git remote URL %s, set %s env variable for proper qodana.cloud reporting", remote, QodanaRemoteUrl)
        return ""
    }
    return remote
}

func validateBranch(branch string, env string) string {
    if branch == "" {
        if env == "github-actions" {
            branch = os.Getenv("GITHUB_REF")
        } else if env == "azure-pipelines" {
            branch = os.Getenv("BUILD_SOURCEBRANCHNAME")
        } else if env == "jenkins" {
            branch = os.Getenv("GIT_BRANCH")
        }
    }
    if branch == "" {
        log.Warnf("Unable to parse git branch, set %s env variable for proper qodana.cloud reporting", QodanaBranch)
        return ""
    }
    return branch
}

func validateJobUrl(ciUrl string, qEnv string) string {
    if strings.HasPrefix(qEnv, "azure") { // temporary workaround for Azure Pipelines
        return getAzureJobUrl()
    }
    _, err := url.ParseRequestURI(ciUrl)
    if err != nil {
        return ""
    }
    return ciUrl
}

// Bootstrap takes the given command (from CLI or qodana.yaml) and runs it.
func Bootstrap(command string, project string) {
    if command != "" {
        var executor string
        var flag string
        switch runtime.GOOS {
        case "windows":
            executor = "cmd"
            flag = "/c"
        default:
            executor = "sh"
            flag = "-c"
        }

        if res, err := RunCmd(project, executor, flag, "\""+command+"\""); res > 0 || err != nil {
            log.Printf("Provided bootstrap command finished with error: %d. Exiting...", res)
            os.Exit(res)
        }
    }
}

func SetEnv(key string, value string) {
    log.Debugf("Setting %s=%s", key, value)
    if os.Getenv(key) == "" && value != "" {
        err := os.Setenv(key, value)
        if err != nil {
            return
        }
        log.Debugf("Set %s=%s", key, value)
    }
}

// getAzureJobUrl returns the Azure Pipelines job URL.
func getAzureJobUrl() string {
    if server := os.Getenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"); server != "" {
        return strings.Join([]string{
            server,
            os.Getenv("SYSTEM_TEAMPROJECT"),
            "/_build/results?buildId=",
            os.Getenv("BUILD_BUILDID"),
        }, "")
    }
    return ""
}

// getSpaceJobUrl returns the Space job URL.
func getSpaceRemoteUrl() string {
    if server := os.Getenv("JB_SPACE_API_URL"); server != "" {
        return strings.Join([]string{
            "ssh://git@git.",
            server,
            "/",
            os.Getenv("JB_SPACE_PROJECT_KEY"),
            "/",
            os.Getenv("JB_SPACE_GIT_REPOSITORY_NAME"),
            ".git",
        }, "")
    }
    return ""
}

// IsGitLab returns true if the current environment is GitLab CI.
func isGitLab() bool {
    return os.Getenv("GITLAB_CI") == "true"
}

// IsBitBucket returns true if the current environment is BitBucket Pipelines.
func isBitBucket() bool {
    return os.Getenv("BITBUCKET_PIPELINE_UUID") != ""
}

// getBitBucketCommit returns the BitBucket commit hash.
func getBitBucketCommit() string {
    return os.Getenv("BITBUCKET_COMMIT")
}

// getBitBucketRepoSlug returns the BitBucket repository slug.
func getBitBucketRepoSlug() string {
    return os.Getenv("BITBUCKET_REPO_SLUG")
}

// sarifResultToCodeClimate converts a SARIF result to a Code Climate issue.
func sarifResultToCodeClimate(r *sarif2.Result) CCIssue {
    fingerprint, ok := r.PartialFingerprints["equalIndicator/v2"].(string)
    if !ok {
        fingerprint = ""
    }
    return CCIssue{
        CheckName:   *r.RuleID,
        Description: *r.Message.Text,
        Fingerprint: fingerprint,
        Severity:    map[string]string{"error": "critical", "warning": "major", "note": "minor"}[*r.Level],
        Location: Location{
            Path: *r.Locations[0].PhysicalLocation.ArtifactLocation.URI,
            Lines: Line{
                Begin: *r.Locations[0].PhysicalLocation.Region.StartLine,
            },
        },
    }
}

func sarifResultToBitBucketAnnotation(result *sarif2.Result) BBAnnotation {
    location := result.Locations[0].PhysicalLocation
    return BBAnnotation{
        Path:     *location.ArtifactLocation.URI,
        Line:     *location.Region.StartLine,
        Message:  *result.Message.Text,
        Severity: map[string]string{"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}[*result.Level],
    }
}

// writeGlCodeQualityReport saves GitLab CodeQuality issues to a file in JSON format
func writeGlCodeQualityReport(issues []CCIssue, sarifPath string) error {
    outputFile := filepath.Join(filepath.Dir(sarifPath), glCodeQualityReport)
    file, err := os.Create(outputFile)
    if err != nil {
        log.Fatalf("Failed to create GitLab CodeQuality report file: %v", err)
    }
    defer func(file *os.File) {
        err := file.Close()
        if err != nil {
            log.Warnf("failed to close GitLab CodeQuality report file: %s", err.Error())
        }
    }(file)
    encoder := json.NewEncoder(file)
    if err := encoder.Encode(issues); err != nil {
        return fmt.Errorf("failed to write GitLab CodeQuality report: %w", err)
    }
    return nil
}

type BBReport struct {
    Title       string         `json:"title"`
    Details     string         `json:"details"`
    Result      string         `json:"result"`
    Reporter    string         `json:"reporter"`
    Annotations []BBAnnotation `json:"annotations"`
}

type BBAnnotation struct {
    Path     string `json:"path"`
    Line     int    `json:"line"`
    Message  string `json:"message"`
    Severity string `json:"severity"`
}

// TODO: move it maybe?
func sendBitBucketReport(annotations []BBAnnotation, guid string) error {
    if len(annotations) == 0 {
        return nil
    }
    report := BBReport{ // TODO
        Title:       "Qodana Results",
        Details:     "Qodana found some issues in your code. Please, take a look at the details below.",
        Result:      "PASSED",
        Reporter:    "JetBrains Qodana",
        Annotations: annotations,
    }
    apiURL := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/commits/%s/reports/%s", getBitBucketRepoSlug(), getBitBucketCommit(), guid)
    jsonValue, _ := json.Marshal(report)
    request, err := http.NewRequest("PUT", apiURL, bytes.NewBuffer(jsonValue))
    if err != nil {
        return err
    }

    request.Header.Set("Content-Type", "application/json")
    client := &http.Client{}
    response, err := client.Do(request)
    if err != nil {
        return err
    }
    defer func(Body io.ReadCloser) {
        err := Body.Close()
        if err != nil {
            log.Warnf("Failed to close response body: %v", err)
        }
    }(response.Body)
    if response.StatusCode >= 300 {
        return fmt.Errorf("failed to send report to BitBucket Code Insights, status code: %d", response.StatusCode)
    }

    return nil
}
