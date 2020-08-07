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

from lib.integration import bitbucket, github, gitlab


def get_git_provider(repo_context):
    if repo_context and repo_context.get("gitProvider"):
        gitProvider = repo_context.get("gitProvider")
        if gitProvider == "bitbucket":
            return bitbucket.Bitbucket()
        elif gitProvider == "gitlab":
            return gitlab.GitLab()
        elif gitProvider == "github":
            return github.GitHub()
    return None
