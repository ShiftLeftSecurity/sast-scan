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
