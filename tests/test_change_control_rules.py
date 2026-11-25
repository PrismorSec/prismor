"""Change-control rules: push to main, terraform, kubectl, helm, cloud CLIs,
gh mutations, sudo. Each rule must fire on the real command and stay quiet on
read-only siblings and on text that merely mentions the command."""

import os
import sys
import unittest

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.policy_engine import PolicyEngine

HITS = {
    "git-branch-force-delete": [
        "git branch -D topic",
        'git -C "my repo" branch --delete topic --force',
        "git branch --force -d topic",
        "git branch -qfd -- topic other",
        "git branch --list; git branch -D topic",
    ],
    "git-clean-force": [
        "git clean -fdx",
        "git clean -d -f -X",
        "git clean --force --quiet -- build/",
        'git -C "my repo" clean -ffdx',
        "git -c color.ui=false clean -f",
        "git clean -f -e -n",
        "git clean -f --exclude=--dry-run",
        "git clean -fe -n",
        "git clean -e-n -f",
        "git clean -fen",
        'git clean -f -e"keep -n"',
        "git clean -f --excl -n",
        "git clean -f > -n",
        "git clean -fdx>/dev/null 2>&1",
        "git clean -fn --no-dry-run",
        "bash -lc 'git clean -fdx'",
        "git clean -f -- -n",
        "git clean -ndx; git clean -fdx",
        "echo 'git clean -n'; git clean -f",
    ],
    "git-stash-delete": [
        "git stash drop",
        "git stash drop -q 'stash@{0}'",
        "git --no-pager stash clear",
        "cd repo && git stash clear",
        "git stash list; git stash drop",
        "sh -c 'git stash clear'",
    ],
    "git-push-protected-branch": [
        "git push origin main",
        "git push -u origin master",
        "git push origin HEAD:main",
        "git push origin +main",
        "cd repo && git push origin main",
        "git -C ../repo push origin main --tags",
    ],
    "terraform-state-change": [
        "terraform apply -auto-approve",
        "terraform -chdir=infra destroy",
        "tofu apply",
        "terragrunt run-all apply",
        "terraform state rm aws_instance.web",
        "TF_LOG=debug terraform apply",
    ],
    "kubectl-cluster-change": [
        "kubectl apply -f deploy.yaml",
        "kubectl -n prod delete pod web-1",
        "kubectl --context=prod scale deploy/web --replicas=0",
        "kubectl rollout restart deploy/web",
        "kubectl drain node-1",
        "oc delete project demo",
    ],
    "helm-release-change": [
        "helm upgrade --install web ./chart",
        "helm -n prod uninstall web",
        "helm rollback web 3",
    ],
    "cloud-cli-mutation": [
        "aws ec2 terminate-instances --instance-ids i-123",
        "aws --profile prod s3api delete-bucket --bucket b",
        "aws s3 rm s3://bucket/key --recursive",
        "aws s3 sync ./dist s3://bucket/site",
        "aws lambda invoke --function-name f out.json",
        "gcloud compute instances delete vm-1",
        "gcloud run deploy svc --image x",
        "gcloud projects add-iam-policy-binding p --member m --role r",
        "az group delete -n rg --yes",
        "az vm deallocate -g rg -n vm",
    ],
    "gh-remote-mutation": [
        "gh pr merge 12 --squash",
        "gh workflow run deploy.yml",
        "gh release create v1.0.0",
        "gh repo delete me/repo --yes",
        "gh secret set TOKEN",
        "gh api -X DELETE repos/me/repo/branches/x",
        "gh api --method=PATCH repos/me/repo",
    ],
    "sudo-command": [
        "sudo apt-get install -y jq",
        "cd /tmp && sudo make install",
        "doas reboot-helper",
    ],
}

MISSES = {
    "git-branch-force-delete": [
        "git branch -d topic", "git branch --delete topic",
        "git branch --list", "git branch --list -- -D",
        "git branch -m old new", "git branch -M old new",
        "git branch -f topic HEAD", "git branch -dr origin/topic",
        "git branch -D -r origin/topic", "git branch -D --help",
        "git branch -d topic && git branch -f other HEAD",
        "git branch -d topic -- -f",
        'git commit -m "git branch -D topic"',
    ],
    "git-clean-force": [
        "git clean -ndx",
        "git clean -fdxn",
        "git clean --dry-run -fdx",
        "git clean -fdx --dry-run",
        'git clean -f "-n"',
        "git clean -f --dry-r",
        "git clean -f --no-dry-run -n",
        "git clean -fn -e --no-dry-run",
        "git clean -fn -- --no-dry-run",
        "bash -lc 'git clean -fn'",
        'git clean -f "build dir" -n',
        "git clean -f -h",
        "git clean --help",
        "git --help clean -f",
        "git clean -i",
        "git clean -- -f",
        "git clean -e -f",
        "git clean > -f",
        "git status --short",
        "git diff",
        'git commit -m "git clean -fdx"',
    ],
    "git-stash-delete": [
        "git stash",
        "git stash push -m 'drop old work'",
        "git stash list",
        "git stash show -p",
        "git stash apply",
        "git stash pop",
        "git stash drop --help",
        "git stash clear -h",
        'git stash clear "--help"',
        "git --help stash clear",
        "sh -c 'git stash drop --help'",
        'echo "git stash clear"',
    ],
    "git-push-protected-branch": [
        "git push origin feature/main-fix",
        "git push origin main-2",
        "git push origin main:feature",
        "git push",
        "git pull origin main",
        'git commit -m "git push origin main later"',
    ],
    "terraform-state-change": [
        "terraform plan -destroy",
        "terraform init",
        "terraform state list",
        "grep terraform apply notes.md",
    ],
    "kubectl-cluster-change": [
        "kubectl get pods",
        "kubectl describe pod create-job-1",
        "kubectl logs deploy/apply",
        "kubectl get pods | grep label",
        "echo kubectl delete pod x",
    ],
    "helm-release-change": [
        "helm list -A",
        "helm template web ./chart",
        "helm repo add bitnami https://charts.bitnami.com/bitnami",
    ],
    "cloud-cli-mutation": [
        "aws sts get-caller-identity",
        "aws ec2 describe-instances",
        "aws s3 ls s3://bucket",
        "aws s3 cp s3://bucket/key .",
        "gcloud compute instances list",
        "gcloud config set project p",
        "az vm list -o table",
        "az account show",
    ],
    "gh-remote-mutation": [
        "gh pr create --fill",
        "gh pr view 12",
        "gh run list",
        "gh api repos/me/repo",
        "gh issue comment 3 --body hi",
    ],
    "sudo-command": [
        "sudo -l",
        "sudo -v",
        "man sudo",
        'git commit -m "document sudo usage"',
        "grep sudo /etc/group",
    ],
}


class ChangeControlRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = PolicyEngine()

    def _ids(self, cmd):
        return {f["ruleId"] for f in self.engine.check_command(cmd)}

    def test_hits(self):
        for rule, cmds in HITS.items():
            for cmd in cmds:
                with self.subTest(rule=rule, cmd=cmd):
                    self.assertIn(rule, self._ids(cmd))

    def test_misses(self):
        for rule, cmds in MISSES.items():
            for cmd in cmds:
                with self.subTest(rule=rule, cmd=cmd):
                    self.assertNotIn(rule, self._ids(cmd))

    def test_warn_only_by_default(self):
        """Opt-in to block: shipped as warn in a category outside block_categories."""
        for f in self.engine.check_command("terraform apply -auto-approve"):
            if f["ruleId"] == "terraform-state-change":
                self.assertEqual(f["category"], "change_control")
                self.assertEqual(f["action"], "warn")
        self.assertNotIn("change_control", self.engine.block_categories)


@pytest.mark.parametrize("rule,command,safe_command", [
    ("git-clean-force", "git clean -fdx", "git clean -ndx"),
    ("git-stash-delete", "git stash clear", "git stash list"),
    ("git-branch-force-delete", "git branch -D topic", "git branch -d topic"),
])
def test_git_work_loss_approval_is_opt_in(tmp_path, rule, command, safe_command):
    from prismor.runtime.runtime import evaluate_tool_call

    event = {"type": "shell", "agent_event": "PreToolUse", "command": command,
             "metadata": {"tool_name": "Bash"}}

    def check():
        return evaluate_tool_call(event=event, workspace=tmp_path,
                                  agent="claude", mode="enforce")

    before = check()
    assert before.allow
    finding = next(f for f in before.findings if f["ruleId"] == rule)
    assert finding["mode"] == "observe"
    (tmp_path / ".prismor").mkdir(exist_ok=True)
    (tmp_path / ".prismor" / "policy.yaml").write_text(
        f"rules:\n  - id: {rule}\n    mode: enforce\n    action: step_up\n")
    assert check().verdict == "step_up"
    event["command"] = safe_command
    assert check().allow
    event["command"] = f"cat <<'EOF' > notes.txt\n{command}\nEOF"
    assert check().allow


if __name__ == "__main__":
    unittest.main()
