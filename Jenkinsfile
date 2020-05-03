#!groovy

properties([disableConcurrentBuilds(), pipelineTriggers([pollSCM('H/3 * * * *')])])

pipeline {
	agent { label 'ubuntu-ci' }
	environment {
		REPO_NAME = "github.com/ShiftLeftSecurity/sast-scan"
		ADMIN_TOKEN = credentials('jenkins-admin-token')
		GITHUB_KEY = '4b3482c3-735f-4c31-8d1b-d8d3bd889348'
	}
	options {
		skipDefaultCheckout()
	}
	stages {
		stage('cleanUp') {
			steps {
				script {
					try {
						deleteDir()
					} catch (err) {
						println("WARNING: Failed to delete directory: " + err)
					}
				}
			}
		}
		stage('getSrc') {
			steps {
				script {
					echo "Checking out sast-scan"
					sshagent(credentials: ["${env.GITHUB_KEY}"]) {
						checkout([
								$class                           : 'GitSCM',
								branches                         : [[name: "*/master"], [name: "*/feature**"]],
								doGenerateSubmoduleConfigurations: false,
								extensions                       : [[
												   $class             : 'SubmoduleOption',
												   disableSubmodules  : false,
												   parentCredentials  : false,
												   recursiveSubmodules: true,
												   reference          : '',
												   trackingSubmodules : false
												   ]],
								submoduleCfg                     : [],
								userRemoteConfigs                : [[
												   url: "ssh://git@${env.REPO_NAME}"
												   ]]
						])
					}
				}
			}
		}

		stage('dockerBuild') {
			steps {
				script {
					env.COMMIT_HASH = sh(returnStdout: true, script: "git rev-parse HEAD | cut -c1-7").trim()
					env.BUILD_DATE = sh(returnStdout: true, script: "date -u +'%Y-%m-%dT%H:%M:%SZ'").trim()
					sh "docker build --build-arg CLI_VERSION=${env.COMMIT_HASH} --build-arg BUILD_DATE=${env.BUILD_DATE} -t shiftleft/sast-scan -t shiftleft/scan -t shiftleft/scan:${env.COMMIT_HASH} ."
					sh "docker build --build-arg CLI_VERSION=${env.COMMIT_HASH} --build-arg BUILD_DATE=${env.BUILD_DATE} -f ci/Dockerfile-java -t shiftleft/scan-java -t shiftleft/scan-java:${env.COMMIT_HASH} ."
					sh "docker build --build-arg CLI_VERSION=${env.COMMIT_HASH} --build-arg BUILD_DATE=${env.BUILD_DATE} -f ci/Dockerfile-csharp -t shiftleft/scan-csharp -t shiftleft/scan-csharp:${env.COMMIT_HASH} ."
					sh "docker build --build-arg CLI_VERSION=${env.COMMIT_HASH} --build-arg BUILD_DATE=${env.BUILD_DATE} -f ci/Dockerfile-oss -t shiftleft/scan-oss -t shiftleft/scan-oss:${env.COMMIT_HASH} ."
				}
			}
		}
		stage('dockerPush') {
			when {
                branch "master"
            }
			steps {
				script {
					withDockerRegistry([credentialsId: '9a3c9d57-9e45-4c3f-b2af-69707fbd0597']) {
						sh "docker push shiftleft/scan"
						sh "docker push shiftleft/sast-scan"
						sh "docker push shiftleft/scan-java"
						sh "docker push shiftleft/scan-csharp"
						sh "docker push shiftleft/scan-oss"
					}
				}
			}
		}
	}
	post {
		failure {
			script {
				notifyFailed()
			}
		}
		aborted {
			script {
				notifyAborted()
			}
		}
		fixed {
			script {
				notifyFixed()
			}
		}
	}
}

def notifyFailed() {
	slackSend (channel: '#team-xyz', color: '#FF0000', message: "FAILED: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
	emailext body: "Build URL: ${env.BUILD_URL} (to view full results, click on \"Console Output\")", attachLog: true, recipientProviders: [[$class: 'CulpritsRecipientProvider']], subject: 'Action Required: Jenkins $JOB_NAME #$BUILD_NUMBER FAILED', to: 'prabhu@shiftleft.io'
}

def notifyAborted() {
	slackSend (channel: '#dev-null', color: '#777777', message: "ABORTED: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
}

def notifyFixed() {
	slackSend (channel: '#team-xyz', color: '#22FF00', message: "FIXED: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
	emailext body: "Build URL: ${env.BUILD_URL} (to view full results, click on \"Console Output\")", attachLog: true, recipientProviders: [[$class: 'CulpritsRecipientProvider']], subject: 'Notice: Jenkins $JOB_NAME #$BUILD_NUMBER FIXED!', to: 'prabhu@shiftleft.io'
}
