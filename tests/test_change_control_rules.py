"""Change-control rules: push to main, terraform, kubectl, helm, cloud CLIs,
gh mutations, sudo. Each rule must fire on the real command and stay quiet on
read-only siblings and on text that merely mentions the command."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.policy_engine import PolicyEngine

HITS = {
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


if __name__ == "__main__":
    unittest.main()
