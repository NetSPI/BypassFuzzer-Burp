#!/usr/bin/env python3
"""Exercise the real Gradle version resolver in disposable Git repositories."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[1]
env = {**os.environ, 'GIT_AUTHOR_NAME': 'BypassFuzzer fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
       'GIT_COMMITTER_NAME': 'BypassFuzzer fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
# An operator's override must not turn local-resolution tests into release tests.
env.pop('ORG_GRADLE_PROJECT_releaseVersion', None)
checks = []

with tempfile.TemporaryDirectory(prefix='bypassfuzzer-versioning-') as scratch:
    fixture = Path(scratch) / 'project'
    fixture.mkdir()
    (fixture / '.gitignore').write_text('.gradle/\nbuild/\n')
    (fixture / 'settings.gradle').write_text("rootProject.name = 'version-fixture'\n")
    (fixture / 'build.gradle').write_text('apply from: ' + json.dumps(str(repo / 'gradle/versioning.gradle'))
            + '\ntasks.register("printVersion") { doLast { println project.version } }\n')

    def git(*args):
        return subprocess.check_output(['git', '-C', str(fixture), *args], env=env, stderr=subprocess.STDOUT, text=True).strip()

    def verify(label, expected, override=None, invalid=False, extra_env=None):
        args = [str(repo / 'build.sh'), '-q', '--console=plain', '-p', str(fixture), 'printVersion']
        if extra_env:
            # A reused JVM retains its original executable search path. Start
            # a fresh one to exercise a genuinely unavailable Git executable.
            args.append('--no-daemon')
        if override is not None:
            args.append('-PreleaseVersion=' + override)
        result = subprocess.run(args, cwd=repo, env={**env, **(extra_env or {})}, capture_output=True, text=True)
        if invalid:
            assert result.returncode != 0 and 'Invalid releaseVersion' in result.stderr, result
        else:
            assert result.returncode == 0, result.stderr
            assert result.stdout.splitlines()[-1] == expected, (label, expected, result.stdout)
        checks.append(label)
        print('Verified ' + label, flush=True)

    verify('source ZIP without Git', '0.0.0-dev')
    git('init', '-q', '-b', 'main')
    verify('repository without commits', '0.0.0-dev')
    git('add', '.')
    git('commit', '-qm', 'Fixture')
    sha = git('rev-parse', '--short=12', 'HEAD')
    verify('untagged commit', '0.0.0-dev.g' + sha)
    (fixture / 'untracked.txt').write_text('Untracked data')
    git('tag', 'not-a-release')
    verify('untracked files and non-version tags ignored', '0.0.0-dev.g' + sha)
    git('tag', 'v1.3')
    verify('two-component clean release tag', '1.3.0')
    git('tag', 'v1.3.1-rc.10')
    git('tag', 'v1.3.1-rc.2')
    verify('semantic prerelease precedence on same commit', '1.3.1-rc.10')
    git('tag', 'v1.3.1')
    verify('highest semantic tag on same commit', '1.3.1')
    (fixture / 'settings.gradle').write_text("rootProject.name = 'modified-fixture'\n")
    verify('tracked unstaged modification', '1.3.1-dev.0.g' + sha + '.dirty')
    git('add', 'settings.gradle')
    verify('tracked staged modification', '1.3.1-dev.0.g' + sha + '.dirty')
    git('commit', '-qm', 'Next commit')
    sha = git('rev-parse', '--short=12', 'HEAD')
    verify('commit after highest tag at nearest tagged commit', '1.3.1-dev.1.g' + sha)
    git('tag', 'v99.0.0-rc.01')
    verify('malformed version tag ignored', '1.3.1-dev.1.g' + sha)
    git('tag', 'v1.4.0-rc.1+fixture')
    verify('prerelease and build metadata retained at tag', '1.4.0-rc.1+fixture')
    (fixture / 'settings.gradle').write_text("rootProject.name = 'next-fixture'\n")
    git('add', 'settings.gradle')
    git('commit', '-qm', 'After prerelease')
    sha = git('rev-parse', '--short=12', 'HEAD')
    verify('development version after prerelease', '1.4.0-rc.1.dev.1.g' + sha)
    verify('release override authoritative', '1.3.1', 'v1.3.1')
    verify('short release override normalized', '1.3.0', 'v1.3')
    verify('override with metadata', '1.4.0-rc.1+build.01', 'v1.4.0-rc.1+build.01')
    for bad in ('', '01.3.1', 'v1.3.1-rc.01', 'v1.3.1-rc..1', '1.3.1+bad..metadata', '1.3.1\nunsafe'):
        verify('invalid override ' + repr(bad), None, bad, invalid=True)
    stub = Path(scratch) / 'bin'
    stub.mkdir()
    (stub / 'git').write_text('#!/bin/sh\nexit 127\n')
    (stub / 'git').chmod(0o755)
    verify('Git unavailable', '0.0.0-dev', extra_env={'PATH': str(stub) + os.pathsep + env['PATH']})

report = repo / 'artifacts/verification/releases/versioning.json'
report.parent.mkdir(parents=True, exist_ok=True)
report.write_text(json.dumps({'checks': checks, 'repositoryTagsModified': False}, indent=2) + '\n')
print(f'Passed {len(checks)} Gradle version-resolution scenarios.')
