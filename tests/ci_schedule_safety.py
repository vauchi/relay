# SPDX-FileCopyrightText: 2026 Mattia Egloff <mattia.egloff@pm.me>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract tests for scheduled-pipeline ownership and side effects."""

from pathlib import Path
import re
import unittest


CI_CONFIG = Path(__file__).parents[1] / ".gitlab-ci.yml"
TOP_LEVEL_KEY = re.compile(r"^[A-Za-z0-9_.:-]+:\s*(?:#.*)?$")


def job_section(name: str) -> str:
    lines = CI_CONFIG.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"{name}:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if TOP_LEVEL_KEY.match(lines[index]):
            end = index
            break
    return "\n".join(lines[start:end])


class ScheduledPipelineSafetyTests(unittest.TestCase):
    def test_schedule_cannot_publish_deploy_or_fan_out(self) -> None:
        for name in (
            "auto-tag:version",
            "publish:package:relay",
            "deploy:trigger",
            "pages",
            "github-mirror",
            "build:docker:arm64",
            "build:docker:manifest",
        ):
            job = job_section(name)
            schedule = job.index('$CI_PIPELINE_SOURCE == "schedule"')
            never = job.index("when: never", schedule)
            branch = job.index("$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH")
            self.assertLess(schedule, never, name)
            self.assertLess(never, branch, name)

        self.assertNotIn("trigger:e2e:", CI_CONFIG.read_text(encoding="utf-8"))

    def test_scheduled_image_cannot_advance_latest(self) -> None:
        build = job_section("build:docker")

        self.assertIn('$CI_PIPELINE_SOURCE == "schedule"', build)
        self.assertIn('[ "$CI_PIPELINE_SOURCE" != "schedule" ]', build)
        self.assertIn("--destination $CI_REGISTRY_IMAGE:latest", build)


if __name__ == "__main__":
    unittest.main()
