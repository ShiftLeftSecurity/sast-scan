# This file is part of Scan.

# Scan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Scan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Scan.  If not, see <https://www.gnu.org/licenses/>.

from abc import ABCMeta, abstractmethod


class GitProvider(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def get_context(cls, repo_context):
        pass

    @classmethod
    @abstractmethod
    def annotate_pr(cls, repo_context, findings_file, report_summary, build_status):
        pass

    @classmethod
    def upload_report(cls, repo_context, findings_file, report_summary, build_status):
        pass

    @classmethod
    def create_status(cls, repo_context, findings_file, report_summary, build_status):
        pass

    @classmethod
    def manage_issues(cls, repo_context, findings_file, report_summary, build_status):
        pass

    @classmethod
    def to_emoji(cls, status):
        emoji_codes = {":white_heavy_check_mark:": "✅", ":cross_mark:": "❌"}
        return emoji_codes.get(status, status)
