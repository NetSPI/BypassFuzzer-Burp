#!/usr/bin/env python3
"""Exercise release workflow commands using temporary CLIs; no GitHub/S3 writes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile
import yaml
from release_version import canonical

repo = Path(__file__).resolve().parents[1]
workflow = yaml.safe_load((repo / '.github/workflows/release.yml').read_text())
build = workflow['jobs']['build-and-upload']
job = workflow['jobs']['publish-manifest']
build_steps = {step['name']: step for step in build['steps']}
steps = {step['name']: step for step in job['steps']}
manifest = repo / 'build/release/bypassfuzzer_version.txt'
version = canonical(manifest.read_text().strip())
jar = repo / 'build/libs/bypassfuzzer.jar'
cli_jar = repo / 'cli/build/libs/bypassfuzzer-cli.jar'
assert workflow['permissions'] == {'contents': 'read'}
assert job['needs'] == 'build-and-upload'
assert build['permissions'] == {'contents': 'write'}
assert job['permissions'] == {'contents': 'read', 'id-token': 'write'}
assert job['concurrency'] == {'group': 'bypassfuzzer-stable-version-manifest', 'cancel-in-progress': False}
assert not any(key.startswith('AWS_') for key in build['env'])
assert not any('aws-actions/' in step.get('uses', '') for step in build['steps'])
assert build_steps['Check out release tag']['with']['fetch-depth'] == 0
assert build_steps['Check out release tag']['with']['ref'] == '${{ github.event.release.tag_name || github.ref }}'
assert build['outputs']['version'] == '${{ steps.version.outputs.version }}'
assert job['env']['BUILD_VERSION'] == '${{ needs.build-and-upload.outputs.version }}'
assert build_steps['Build and test']['env']['RELEASE_VERSION'] == '${{ steps.version.outputs.release_version }}'
assert build_steps['Verify packaged versions']['env']['BUILD_VERSION'] == '${{ steps.version.outputs.version }}'
names = list(build_steps)
assert names.index('Build and test') < names.index('Verify packaged versions') < names.index('Upload JARs to release') < names.index('Preserve generated version manifest')
assert build_steps['Upload JARs to release']['if'] == "github.event_name == 'release'"
for name in ('Build and test', 'Verify packaged versions', 'Upload JARs to release', 'Preserve generated version manifest'):
    assert 'always()' not in build_steps[name].get('if', '')
artifact = build_steps['Preserve generated version manifest']['with']
download = steps['Download generated version manifest']['with']
assert artifact['name'] == download['name'] and artifact['if-no-files-found'] == 'error'
assert artifact['path'] == 'build/release/bypassfuzzer_version.txt' and download['path'] == 'build/release'
for name in ('Check out publishing scripts', 'Download generated version manifest', 'Configure AWS credentials', 'Update S3 version manifest'):
    assert steps[name]['if'] == "steps.manifest_config.outputs.publish == 'true'"
assert job['env']['S3_VERSION_MANIFEST_URI'] == 's3://wapen-tools-1/bypassfuzzer_version.txt'
check = repo / 'scripts/check-release-version.py'
for tag, built, expected in [('v1.2', '1.2.0', 0), ('v1.3.0', '1.2.0', 1),
        ('v1.2.0-rc.1', '1.2.0', 1), ('not-a-version', '1.2.0', 1),
        ('v1.3.1-rc.01', '1.3.1-rc.01', 1), ('v1.3.1+one', '1.3.1+two', 1)]:
    result = subprocess.run(['python3', str(check), tag, built], capture_output=True, text=True)
    assert (result.returncode != 0) == bool(expected), result
subprocess.run(['python3', str(check), version, version, '--jar', str(jar), '--cli-jar', str(cli_jar), '--manifest', str(manifest)], check=True)
cli_version = subprocess.check_output(['java', '-jar', str(cli_jar), '--version'], text=True).strip()
assert cli_version == 'BypassFuzzer CLI ' + version, cli_version

with tempfile.TemporaryDirectory(prefix='bypassfuzzer-release-') as scratch:
    temp = Path(scratch)
    output, summary, calls = temp/'output', temp/'summary', temp/'calls'
    base = {key: value for key, value in os.environ.items() if not key.startswith('AWS_')}
    base.update(GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary), CALLS=str(calls),
                GITHUB_EVENT_NAME='release', GITHUB_REPOSITORY='intrudir/BypassFuzzer-Burp',
                PATH=str(temp)+os.pathsep+os.environ['PATH'])
    def execute(code, overrides=None, cwd=repo):
        return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', code], cwd=cwd,
                              env={**base, **(overrides or {})}, capture_output=True, text=True)

    cases = [('', '', '', '1.3.1', 'release', 'intrudir/BypassFuzzer-Burp', False),
        ('us-east-1', '', '', '1.3.1', 'release', 'intrudir/BypassFuzzer-Burp', False),
        ('', 'fixture-role', '', '1.3.1', 'release', 'intrudir/BypassFuzzer-Burp', False),
        ('us-east-1', 'fixture-role', 'true', '1.3.1', 'release', 'intrudir/BypassFuzzer-Burp', False),
        ('us-east-1', 'fixture-role', '', '1.3.1-rc.1', 'release', 'intrudir/BypassFuzzer-Burp', False),
        ('us-east-1', 'fixture-role', '', '1.3.1', 'workflow_dispatch', 'intrudir/BypassFuzzer-Burp', False),
        ('us-east-1', 'fixture-role', '', '1.3.1', 'release', 'fixture/BypassFuzzer-Burp', False),
        ('us-east-1', 'fixture-role', '', '1.3.1+build-meta', 'release', 'intrudir/BypassFuzzer-Burp', True),
        ('us-east-1', 'fixture-role', '', '1.3.1', 'release', 'intrudir/BypassFuzzer-Burp', True)]
    for region, role, prerelease, built, event, repository, publish in cases:
        output.write_text(''); summary.write_text('')
        result = execute(steps['Check manifest publishing configuration']['run'],
            {'AWS_REGION':region, 'AWS_ROLE_TO_ASSUME':role, 'PRERELEASE':prerelease,
             'BUILD_VERSION':built, 'GITHUB_EVENT_NAME':event, 'GITHUB_REPOSITORY':repository})
        assert result.returncode == 0, result.stderr
        assert output.read_text().strip() == 'publish=' + str(publish).lower()
        if event == 'release' and repository == 'intrudir/BypassFuzzer-Burp' and (not role or not region):
            assert 'not updated' in summary.read_text()

    aws = temp / 'aws'
    aws.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
with open(os.environ['CALLS'],'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1:3] == ['s3api','get-object']:
    mode=os.environ.get('CURRENT','missing')
    if mode in ('missing','denied','network'):
        message='(NoSuchKey)' if mode=='missing' else '(AccessDenied)' if mode=='denied' else 'Connection failed'
        print(message,file=sys.stderr); sys.exit(2 if mode=='missing' else 32)
    pathlib.Path(sys.argv[-1]).write_text(mode+'\\n')
else:
    if os.environ.get('FAIL_AWS'): sys.exit(32)
    pathlib.Path(os.environ['CAPTURED_AWS']).write_text(json.dumps({'args':sys.argv[1:],'body':pathlib.Path(sys.argv[3]).read_text()}))
''')
    aws.chmod(0o755)
    candidate = temp / 'bypassfuzzer_version.txt'
    candidate.write_text('1.3.1\n')
    captured = temp / 'aws.json'
    publish_code = steps['Update S3 version manifest']['run'].replace('build/release/bypassfuzzer_version.txt', str(candidate))
    publish_env = {'BUILD_VERSION':'1.3.1', 'S3_VERSION_MANIFEST_URI':job['env']['S3_VERSION_MANIFEST_URI'], 'CAPTURED_AWS':str(captured)}
    for current, should_write, status in [('missing', True, 0), ('1.3.0', True, 0), ('1.3.1', False, 0),
            ('1.3.2', False, 0), ('denied', False, 32), ('network', False, 32),
            ('garbage', False, 1), ('1.4.0-rc.1', False, 1)]:
        captured.unlink(missing_ok=True); summary.write_text(''); calls.write_text('')
        result = execute(publish_code, {**publish_env, 'CURRENT':current})
        assert result.returncode == status, (current, result.stderr)
        assert captured.exists() == should_write, current
        recorded = [json.loads(line) for line in calls.read_text().splitlines()]
        assert recorded[0][0:6] == ['s3api','get-object','--bucket','wapen-tools-1','--key','bypassfuzzer_version.txt']
        if should_write:
            upload = json.loads(captured.read_text())
            assert upload['args'] == ['s3','cp',str(candidate),job['env']['S3_VERSION_MANIFEST_URI'],
                '--content-type','text/plain','--cache-control','no-cache','--acl','public-read']
            assert upload['body'] == '1.3.1\n' and 'Published 1.3.1' in summary.read_text()
    candidate.write_text('1.3.2\n'); calls.write_text('')
    result = execute(publish_code, publish_env)
    assert result.returncode != 0 and not calls.read_text(), 'Mismatched artifact reached AWS'
    candidate.write_text('1.3.1\n')

    # Exercise the actual workflow shell commands with a Gradle boundary stub.
    project = temp / 'project'; project.mkdir()
    (project / 'scripts').symlink_to(repo / 'scripts', target_is_directory=True)
    (project / 'build/libs').mkdir(parents=True)
    (project / 'build/release').mkdir(parents=True)
    (project / 'build/libs/bypassfuzzer.jar').symlink_to(jar)
    (project / 'cli/build/libs').mkdir(parents=True)
    (project / 'cli/build/libs/bypassfuzzer-cli.jar').symlink_to(cli_jar)
    local_manifest = project / 'build/release/bypassfuzzer_version.txt'
    local_manifest.write_text(manifest.read_text())
    (project / 'gradlew').write_text('''#!/usr/bin/env python3
import json,os,sys
with open(os.environ['CALLS'],'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')
if 'printVersion' in sys.argv:
    print(next((arg.split('=',1)[1] for arg in sys.argv if arg.startswith('-PreleaseVersion=')), '0.0.0-dev.gfixture'))
elif os.environ.get('FAIL_BUILD'): sys.exit(41)
''')
    (project / 'gradlew').chmod(0o755)
    gh = temp / 'gh'; captured_gh = temp / 'gh.json'
    gh.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
assert not any(key.startswith('AWS_') for key in os.environ)
if os.environ.get('FAIL_GH'): sys.exit(42)
pathlib.Path(os.environ['CAPTURED_GH']).write_text(json.dumps(sys.argv[1:]))
''')
    gh.chmod(0o755)
    for tag in ('not-a-version', 'v1.3.1-rc.01'):
        output.write_text(''); calls.write_text('')
        result = execute(build_steps['Resolve build version']['run'], {'RELEASE_TAG':tag}, project)
        assert result.returncode != 0 and not calls.read_text(), 'Invalid tag reached Gradle'
    output.write_text(''); calls.write_text('')
    result = execute(build_steps['Resolve build version']['run'], {'RELEASE_TAG':'v' + version}, project)
    assert result.returncode == 0, result.stderr
    resolved = dict(line.split('=',1) for line in output.read_text().splitlines())
    assert resolved == {'version':version, 'release_version':version}
    run_env = {'RELEASE_TAG':'v' + version, 'RELEASE_VERSION':version, 'BUILD_VERSION':version,
               'UPDATE_MANIFEST_URL':'', 'CAPTURED_GH':str(captured_gh)}
    for name in ('Check release tag matches the built version', 'Build and test', 'Verify packaged versions', 'Upload JARs to release'):
        result = execute(build_steps[name]['run'], run_env, project)
        assert result.returncode == 0, (name, result.stderr)
    gradle_calls = [json.loads(line) for line in calls.read_text().splitlines()]
    assert all('-PreleaseVersion=' + version in args for args in gradle_calls)
    assert json.loads(captured_gh.read_text()) == ['release','upload','v' + version,'build/libs/bypassfuzzer.jar','cli/build/libs/bypassfuzzer-cli.jar','--clobber']
    result = execute(build_steps['Build and test']['run'], {**run_env,'FAIL_BUILD':'1'}, project)
    assert result.returncode == 41
    result = execute(build_steps['Upload JARs to release']['run'], {**run_env,'FAIL_GH':'1'}, project)
    assert result.returncode == 42
    local_manifest.write_text('99.0.0\n')
    result = execute(build_steps['Verify packaged versions']['run'], run_env, project)
    assert result.returncode != 0
    result = execute(publish_code, {**publish_env,'CURRENT':'missing','FAIL_AWS':'1'})
    assert result.returncode == 32 and captured_gh.exists()
    output.write_text(''); calls.write_text('')
    result = execute(build_steps['Resolve build version']['run'], {'GITHUB_EVENT_NAME':'workflow_dispatch','RELEASE_TAG':''}, project)
    assert result.returncode == 0 and 'release_version=\n' in output.read_text()
    assert '-PreleaseVersion' not in calls.read_text()
    # A stale runtime version or JAR manifest must each block publication.
    for runtime, implementation in [('99.0.0',version), (version,'99.0.0')]:
        bad_jar = temp / 'bad.jar'
        with zipfile.ZipFile(bad_jar, 'w') as archive:
            archive.writestr('bypassfuzzer-build.properties', 'version=' + runtime + '\n')
            archive.writestr('META-INF/MANIFEST.MF', 'Implementation-Version: ' + implementation + '\r\n')
        result = subprocess.run(['python3',str(check),version,'--jar',str(bad_jar)], capture_output=True, text=True)
        assert result.returncode != 0
    with zipfile.ZipFile(bad_jar, 'w') as archive:
        archive.writestr('META-INF/MANIFEST.MF', 'Implementation-Version: 99.0.0\r\n')
    result = subprocess.run(['python3', str(check), version, '--cli-jar', str(bad_jar)],
                            capture_output=True, text=True)
    assert result.returncode != 0, 'A stale CLI version reached publication'

report = repo / 'artifacts/verification/releases/report.json'
report.parent.mkdir(parents=True, exist_ok=True)
report.write_text(json.dumps({'version':version, 'realJarMetadataVerified':True, 'realCliJarMetadataVerified':True,
    'cliVersionCommandVerified':True,
    'releaseVersionPropagationVerified':True, 'tagMismatchRejected':True, 'invalidTagsRejectedBeforeBuild':True,
    'missingCredentialsReported':True, 'prereleaseForkManualSkipped':True, 'manifestDowngradePrevented':True,
    'manifestReadFailureBlocksWrite':True, 'releaseUploadIndependentOfAws':True,
    'manifestArtifactTransferVerified':True, 'buildUploadAndS3FailureVerified':True,
    'realGitHubWrite':False, 'realS3Write':False}, indent=2)+'\n')
print('Verified real JAR versions, release workflow commands, publication boundaries, and monotonic S3 updates using stub CLIs.')
