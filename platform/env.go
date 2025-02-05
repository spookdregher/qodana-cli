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
	"fmt"
	cienvironment "github.com/cucumber/ci-environment/go"
	log "github.com/sirupsen/logrus"
	"net/url"
	"os"
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
)

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
