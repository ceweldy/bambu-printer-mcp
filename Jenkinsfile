// Runs a script inside a throwaway container. Source (including .git) is
// streamed in with tar, so no host bind mounts are needed.
def inDocker(String image, String script) {
    writeFile file: '.ci-step.sh', text: "set -eux\n" + script + "\n"
    sh """
        set -eu
        tar -cf - . | docker run --rm -i --memory 6g --cpus 4 \\
          -e CI=true -e HOME=/tmp/home -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0="*" ${image} \\
          sh -c 'mkdir -p /src /tmp/home && cd /src && tar -xf - && git config --global --add safe.directory /src 2>/dev/null || true; sh .ci-step.sh'
    """
}

def ciSteps = '''npm ci
npm test
node scripts/audit-allowlist.mjs
npm run privacy:check
npm run privacy:history
npm pack --dry-run'''

pipeline {
    agent { label 'linux-docker' }
    options { timeout(time: 20, unit: 'MINUTES'); timestamps(); disableConcurrentBuilds(); buildDiscarder(logRotator(numToKeepStr: '20')) }
    stages {
        stage('Checkout history') { steps { sh 'git fetch --unshallow --quiet || true' } }
        stage('Validate') {
            parallel {
                stage('Node 20') { steps { script { inDocker('node:20', ciSteps) } } }
                stage('Node 22') { steps { script { inDocker('node:22', ciSteps) } } }
            }
        }
    }
    post { always { deleteDir() } }
}
