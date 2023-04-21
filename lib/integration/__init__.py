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
